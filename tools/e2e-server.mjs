import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn, spawnSync} from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const python = join(root, process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python');
const directory = mkdtempSync(join(tmpdir(), 'snc-e2e-'));
const env = {...process.env, SNC_STATE_DIR: directory, SNC_MODE: 'demo', SNC_SERVER: '192.0.2.15', SNC_PORT: '7446', SNC_BIND: '127.0.0.1', SNC_ALLOWED_HOSTS: '127.0.0.1,localhost'};
delete env.SNC_NGINX_ROOT;
delete env.SNC_LOG_ROOT;
const initialized = spawnSync(python, ['bootstrap.py'], {cwd: root, env, stdio: 'inherit'});
if (initialized.status !== 0) process.exit(initialized.status || 1);
const server = spawn(python, ['serve.py'], {cwd: root, env, stdio: 'inherit'});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.kill());
server.on('exit', (code) => process.exit(code || 0));