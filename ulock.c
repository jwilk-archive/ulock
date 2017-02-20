/* Copyright © 2006-2013 Jakub Wilk <jwilk@jwilk.net>.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <security/pam_appl.h>

#define LOCK_ALL
#define FAIL_DELAY 1000000

static struct vt_mode old_vtm;
static struct termios old_tattr;

static ssize_t writes(int fd, const char *message)
{
  return write(fd, message, strlen(message));
}

static void fatal(char *message)
{
  writes(STDERR_FILENO, message);
  exit(EXIT_FAILURE);
}

#ifdef LOCK_ALL
static void restore_tty_mode()  { ioctl(STDIN_FILENO, VT_SETMODE, &old_vtm); }
#endif
static void restore_tty_attrs() { tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_tattr); }

static void init_tty(void)
{
  if (isatty(STDIN_FILENO) && ioctl(STDIN_FILENO, VT_GETMODE, &old_vtm) == -1)
    fatal("The terminal is not a virtual console. I refuse to continue.\n");
#ifdef LOCK_ALL
  struct vt_mode vtm = old_vtm;
  vtm.mode = VT_PROCESS;
  vtm.relsig = SIGUSR1;
  vtm.acqsig = SIGUSR2;
  if (ioctl(STDIN_FILENO, VT_SETMODE, &vtm) == -1)
    fatal("Error while setting the terminal mode.\n");
  atexit(restore_tty_mode);
#endif

  if (tcgetattr(STDIN_FILENO, &old_tattr) == -1)
    fatal("Error while getting the terminal attributes.\n");
  struct termios tattr = old_tattr;
  tattr.c_iflag &= ~(BRKINT | ISIG);
  tattr.c_iflag |= IGNBRK;
  tattr.c_lflag &= ~(ECHO | ECHOCTL | ICANON);
  tattr.c_cc[VMIN] = 1;
  tattr.c_cc[VTIME] = 0;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr) == -1)
    fatal("Error while setting the terminal attributes.\n");
  atexit(restore_tty_attrs);
}

static void canonize_tty()
{
  struct termios tattr;
  if (tcgetattr(STDIN_FILENO, &tattr) == -1)
    fatal("Error while getting the terminal attributes.\n");
  tattr.c_lflag |= ICANON;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr) == -1)
    fatal("Error while setting the terminal attributes.\n");
}

static void init_pty(int fd, struct winsize *wsize, struct termios tattr)
{
  if (ioctl(fd, TIOCSCTTY, 0) == -1)
    fatal("<child> Error while setting up the controlling terminal.\n");

  for (int i = 0; i <= 2; i++)
    if (dup2(fd, i) == -1)
      fatal("<child> Error while duplicating file descriptors.\n");
  if (fd > 2)
    close(fd);

  tattr.c_iflag = BRKINT | IGNPAR | ICRNL | IXON | IMAXBEL;
  tattr.c_oflag = OPOST | ONLCR;
  tattr.c_cflag = CS8 | CREAD;
  tattr.c_lflag = ISIG | ICANON | IEXTEN | ECHO | ECHOE | ECHOK;
  if (tcsetattr(STDIN_FILENO, TCSANOW, &tattr) == -1)
    fatal("<child> Error while setting the terminal attributes.\n");
  if (ioctl(STDIN_FILENO, TIOCSWINSZ, wsize) == -1)
    fatal("<child> Error while setting the terminal size.\n");
}

static void drop_privileges(void)
{
  setuid(getuid());
  setgid(getgid());
}

char *open_ptm(int *ptm)
{
  if ((*ptm = getpt()) == -1)
    return NULL;
  if (grantpt(*ptm) == -1)
    return NULL;
  if (unlockpt(*ptm) == -1)
    return NULL;
  return ptsname(*ptm);
}

static jmp_buf env;

static void signal_handler(int sig)
{
  switch (sig)
  {
  case SIGUSR1:
    ioctl(STDIN_FILENO, VT_RELDISP, 0);
    break;
  case SIGUSR2:
    ioctl(STDIN_FILENO, VT_RELDISP, VT_ACKACQ);
    break;
  case SIGCHLD:
    longjmp(env, sig);
  }
}

static void setup_signals(void)
{
  struct sigaction sa = { .sa_handler = signal_handler, .sa_flags = 0 };
  sigset_t ss;
  do
  {
    if (sigfillset(&ss) == -1) break;
    if (sigemptyset(&sa.sa_mask) == -1) break;
    if (sigaction(SIGCHLD, &sa, NULL) == -1 || sigdelset(&ss, SIGCHLD) == -1) break;
    if (sigaction(SIGUSR1, &sa, NULL) == -1 || sigdelset(&ss, SIGUSR1) == -1) break;
    if (sigaction(SIGUSR2, &sa, NULL) == -1 || sigdelset(&ss, SIGUSR2) == -1) break;
    if (sigprocmask(SIG_SETMASK, &ss, NULL) == -1) break;
    return;
  }
  while (false);
  fatal("Error while setting up signal handlers.\n");
}

static void child_setup_signals(void)
{
  do
  {
    struct sigaction sa = { .sa_handler = SIG_DFL, .sa_flags = 0 };
    if (sigemptyset(&sa.sa_mask) == -1) break;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) break;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) break;
    if (sigaction(SIGUSR2, &sa, NULL) == -1) break;
    if (sigprocmask(SIG_SETMASK, &sa.sa_mask, NULL) == -1) break;
    return;
  }
  while (false);
  fatal("<child> Error while setting up signal handlers.\n");
}

static void invoke_command(char *command, char **argv, pid_t *child_pid, int *ptm)
{
  char* slavename = open_ptm(ptm);
  if (slavename == NULL)
    fatal("Error while opening pseudo-terminal.\n");

  struct winsize wsize;
  if (ioctl(STDIN_FILENO, TIOCGWINSZ, &wsize) == -1)
    fatal("Error while getting the terminal size.\n");

  struct termios attr;
  if (tcgetattr(*ptm, &attr) == -1)
    fatal("Error while getting the pseudo-terminal attributes.\n");

  switch (*child_pid = fork())
  {
  case -1:
    fatal("Fork failed.\n");
  case 0:
    /* child: */
    drop_privileges();
    if (close(*ptm) == -1)
      fatal("<child> Error while closing the master pseudo-terminal\n");
    if (setsid() == -1)
      fatal("<child> Error while creating a session\n");
    assert(slavename != NULL);
    int pts = open(slavename, O_RDWR);
    if (pts == -1)
      fatal("<child> Error while opening the slave pseudo-terminal\n");
    init_pty(pts, &wsize, attr);

    child_setup_signals();
    execvp(command, argv);
    fatal("<child> Execution failed.\n");
  default:
    /* parent: */
    return;
  }
}

static void clear(void)
{
  writes(STDOUT_FILENO, "\033[0m\033[H\033[J");
}

static int read_fd(int fd)
{
  char buffer[1 << 10];
  ssize_t size = read(fd, buffer, sizeof buffer);
  if (size > 0)
    (void) write(STDOUT_FILENO, buffer, size);
  return size;
}

static int ulock_conv(int num_msg, const struct pam_message **msgm, struct pam_response **response, void *appdata_ptr)
{
  appdata_ptr = appdata_ptr;

  if (num_msg <= 0)
    return PAM_CONV_ERR;

  struct pam_response *reply = calloc(num_msg, sizeof(struct pam_response));
  if (reply == NULL)
    return PAM_CONV_ERR;

  for (int i = 0; i < num_msg; i++)
  {
    char *string = NULL;
    switch (msgm[i]->msg_style)
    {
    case PAM_PROMPT_ECHO_OFF:
    case PAM_PROMPT_ECHO_ON:
      string = calloc(1 << 8, 1);
      if (string == NULL)
        goto fail;
      ssize_t size = read(STDIN_FILENO, string, 1 << 8);
      if (size < 0)
      {
        free(string);
        goto fail;
      }
      else if (size > 0)
        string[size - 1] = '\0';
      writes(STDOUT_FILENO, "\n");
      break;
    case PAM_ERROR_MSG:
    case PAM_TEXT_INFO:
      continue;
    default:
      goto fail;
    }
    if (string != NULL)
    {
      reply[i].resp_retcode = 0;
      reply[i].resp = string;
      string = NULL;
    }
  }
  *response = reply;
  reply = NULL;
  return PAM_SUCCESS;
fail:
  if (reply != NULL)
  for (int i = 0; i < num_msg; i++)
    if (reply[i].resp != NULL)
      free(reply[i].resp);
  free(reply);
  return PAM_CONV_ERR;
}

void check_password(void)
{
  static struct pam_conv conv =
  {
    ulock_conv,
    NULL
  };
  pam_handle_t *pamh;
  char username[1 << 8];
  username[0] = '\0';
  strncat(username, getpwuid(getuid())->pw_name, (sizeof username) - 1);
  pam_start("ulock", username, &conv, &pamh);
  writes(STDOUT_FILENO, "The terminal is now locked. Please enter the password to unlock it.\n");
  char *username2 = username;
  for (int i = 0; ; i++)
  {
    int pam_error;
    writes(STDOUT_FILENO, username2);
    writes(STDOUT_FILENO, "'s password: ");
    pam_error = pam_set_item(pamh, PAM_USER, username2);
    if (pam_error != PAM_SUCCESS)
      break;
    pam_error = pam_fail_delay(pamh, FAIL_DELAY);
    if (pam_error != PAM_SUCCESS)
      break;
    pam_error = pam_authenticate(pamh, 0);
    if (pam_error == PAM_SUCCESS)
    {
      pam_end(pamh, PAM_SUCCESS);
      return;
    }
    if (pam_error == PAM_ABORT)
      break;
    if (pam_error == PAM_MAXTRIES)
    {
      writes(STDOUT_FILENO, "Erm, one minute penalty...\n");
      sleep(60);
    }
    username2 = (username2 == username) ? "root" : username;
  }
  pam_end(pamh, PAM_SUCCESS);
  fatal("Something went *SERIOUSLY* wrong\n");
}

static bool is_shadow_group(gid_t gid)
{
  struct group *group = getgrgid(gid);
  return (group != NULL && strcmp(group->gr_name, "shadow") == 0);
}

static void check_privileges()
{
  if (geteuid() == 0)
    return;
  if (is_shadow_group(getegid()))
    return;
  int ngroups = getgroups (0, NULL);
  gid_t gids[ngroups];
  ngroups = getgroups(ngroups, gids);
  for (int i = 0; i < ngroups; i++)
    if (is_shadow_group(gids[i]))
      return;
  fatal("The user is not a member of the shadow group. I cowardly refuse to continue.\n");
}

int main(int argc, char **argv)
{
  check_privileges();
  clear();
  init_tty();
  setup_signals();

  struct pollfd ufds[2] =
  {
    { .fd = STDIN_FILENO, .events = POLLIN, .revents = 0 },
    { .fd = -1, .events = POLLIN, .revents = 0 }
  };

  if (setjmp(env) == SIGCHLD)
  {
    wait(NULL);
    if (ufds[1].fd != -1)
      while (read_fd(ufds[1].fd) > 0);
    clear();
    canonize_tty();
    check_password();
    return EXIT_SUCCESS;
  }

  static pid_t child_pid;
  if (argc < 2)
    invoke_command("/bin/true", (char*[]) { "/bin/true" }, &child_pid, &ufds[1].fd);
  else
    invoke_command(argv[1], argv + 1, &child_pid, &ufds[1].fd);
  while (poll(ufds, 2, -1) > 0)
  {
    if (ufds[0].revents)
    {
      char ch;
      (void) read(STDIN_FILENO, &ch, 1);
      kill(child_pid, SIGINT);
      while (poll(ufds + 1, 1, 750) == 1)
        read_fd(ufds[1].fd);
      kill(child_pid, SIGTERM);
      while (poll(ufds + 1, 1, 750) == 1)
        read_fd(ufds[1].fd);
      break;
    }
    if (ufds[1].revents && read_fd(ufds[1].fd) < 0)
      break;
  }
  kill(child_pid, SIGKILL);
  do pause(); while (true);
  return EXIT_FAILURE;
}

/* vim:set ts=2 sts=2 sw=2 et: */
