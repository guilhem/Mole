#!/usr/bin/env python3
"""Exercise managed sudo prompts with a harmless executable inside a real PTY."""
import fcntl
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]


def own_terminal():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def run_pty(script, env, interrupt=False, answer=True):
    master, slave = pty.openpty()
    process = subprocess.Popen(
        ['/bin/bash', '--noprofile', '--norc', '-c', script],
        stdin=slave, stdout=slave, stderr=slave, env=env,
        preexec_fn=own_terminal)
    output = b''
    prompts = 0
    deadline = time.monotonic() + 15
    try:
        while process.poll() is None:
            assert time.monotonic() < deadline, output.decode(errors='replace')
            if select.select([master], [], [], .05)[0]:
                output += os.read(master, 4096)
            if output.count(b'AUTH_PROMPT:') > prompts:
                prompts += 1
                if interrupt:
                    os.write(master, b'\x03')
                elif answer:
                    # Longer than the test's quick-probe budget: a prompt
                    # needs an authorization budget, not a metadata deadline.
                    time.sleep(.4)
                    os.write(master, b'dummy-input\n')
        while select.select([master], [], [], .05)[0]:
            chunk = os.read(master, 4096)
            if not chunk:
                break
            output += chunk
        text = output.decode(errors='replace').replace('\r', '')
        assert process.returncode == 0, text
        return text
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        os.close(master)
        os.close(slave)


with tempfile.TemporaryDirectory(prefix='mole-sudo-pty-') as scratch:
    scratch = Path(scratch)
    sudo = scratch / 'sudo'
    sudo.write_text(f'#!{sys.executable}\n' + r'''
import os
import sys
args = sys.argv[1:]
assert args.pop(0) == '-n', args
sys.stderr.write('AUTH_PROMPT:' + args[0] + '\n')
sys.stderr.flush()
with open('/dev/tty', 'rb', buffering=0) as tty:
    assert tty.readline().strip() == b'dummy-input'
if args == ['test', '-L', '/Library/Caches']:
    sys.exit(1)
if args[0] == 'batch':
    data = sys.stdin.buffer.read()
    assert data == b'one\0two with spaces\0', data
    sys.stdout.write('BATCH_OK\n')
elif args[0] not in ('true', 'test', 'find'):
    sys.exit(99)
''')
    sudo.chmod(0o755)
    env = dict(os.environ, PATH=str(scratch) + ':' + os.environ['PATH'],
               HOME=str(scratch), TEST_ROOT=str(root), MOLE_TEST_MODE='0',
               MOLE_TEST_NO_AUTH='0', MOLE_TIMEOUT_QUICK_DETECT_SEC='0.2',
               MOLE_TIMEOUT_DISK_VERIFY_SEC='4', MO_DEBUG='0')
    setup = r'''
source "$TEST_ROOT/lib/core/file_ops.sh"
MO_TIMEOUT_BIN=""
MO_TIMEOUT_PERL_BIN=/usr/bin/perl
stop_section_spinner() { echo SPINNER_STOPPED; }
'''
    result = run_pty(setup + r'''
safe_sudo_find_delete /Library/Caches '*.cache' 7 f 5 "$((SECONDS + 10))"
mole_tty_is_foreground
echo "SCAN_OK:$MOLE_SAFE_SUDO_FIND_DELETE_COUNT"
# The same transport must leave a deletion batch's NUL-delimited stdin intact.
# Even with another backend installed, explicit TTY mode uses the Perl helper.
MO_TIMEOUT_BIN=/bin/false
_MOLE_SUDO_FOREGROUND=1
_MOLE_SUDO_FOREGROUND_DEADLINE=$((SECONDS + 10))
printf 'one\0two with spaces\0' | _mole_bounded_sudo 0.2 -n batch
mole_tty_is_foreground
echo RESTORED
''', env)
    assert result.index('SPINNER_STOPPED') < result.index('AUTH_PROMPT:'), result
    assert 'SCAN_OK:0' in result and 'BATCH_OK' in result and 'RESTORED' in result, result

    for interrupt, expected in ((False, 124), (True, 130)):
        result = run_pty(setup + r'''
rc=0
run_with_timeout --foreground-tty 0.7 sudo -n true < /dev/null || rc=$?
mole_tty_is_foreground
echo "RESTORED:$rc"
''', env, interrupt=interrupt, answer=False)
        assert f'RESTORED:{expected}' in result, result

    result = run_pty(setup + r'''
# A background caller must not acquire this new interactive context.
safe_sudo_find_delete /Library/Caches '*.cache' 7 f 5 "$((SECONDS + 5))" < /dev/null &
worker=$!
wait "$worker" || rc=$?
mole_tty_is_foreground
echo "BACKGROUND_DONE:${rc:-0}"
''', env, answer=False)
    assert 'SPINNER_STOPPED' not in result and 'AUTH_PROMPT:' not in result, result
    assert 'BACKGROUND_DONE:124' in result, result

print('PASS: foreground prompts, batch stdin, timeout/Ctrl-C restoration, background isolation')
