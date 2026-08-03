import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const publicRoot = path.join(projectRoot, 'public');
const offlineRoot = process.env.OFFLINE_RELEASE_ROOT || 'F:\\Digital Awareness & Literacy Magazine\\Offline Learning Hub';
const liveArgument = process.argv.find((argument) => argument.startsWith('--live='));
const liveUrl = liveArgument ? liveArgument.slice('--live='.length).replace(/\/$/, '') : null;
const release = JSON.parse(fs.readFileSync(path.join(publicRoot, 'release.json'), 'utf8'));
const roots = ['fonts', 'monthly-covers', 'course-pages', 'downloads'];
const directFiles = ['index.html', 'styles.css', 'gateway.js', 'digital-literacy-gateway.png', 'cover-schedule.js', 'learning.js', 'publication-reader.js', 'learning.html', 'cybershieldlogo.png', 'release.json'];

const walk = (root, directory) => {
    const fullDirectory = path.join(root, directory);
    return fs.readdirSync(fullDirectory, { withFileTypes: true }).flatMap((entry) => {
        const relative = path.join(directory, entry.name);
        return entry.isDirectory() ? walk(root, relative) : [relative];
    });
};

const files = [...directFiles, ...roots.flatMap((directory) => walk(publicRoot, directory))];
const hash = (filePath) => crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
const mismatches = files.filter((relative) => {
    const offlineFile = path.join(offlineRoot, relative);
    return !fs.existsSync(offlineFile) || hash(path.join(publicRoot, relative)) !== hash(offlineFile);
});

if (mismatches.length) {
    console.error(`Offline release mismatch (${mismatches.length} files):\n${mismatches.join('\n')}`);
    process.exit(1);
}

console.log(`Workspace and offline release match: ${release.release} (${files.length} files).`);

if (liveUrl) {
    const response = await fetch(`${liveUrl}/release.json?verify=${encodeURIComponent(release.release)}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Live release manifest returned HTTP ${response.status}.`);
    const liveRelease = await response.json();
    if (liveRelease.release !== release.release) throw new Error(`Live release is ${liveRelease.release}; expected ${release.release}.`);
    console.log(`Live release matches: ${liveRelease.release}.`);
}
