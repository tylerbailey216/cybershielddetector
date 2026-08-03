import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readerPath = path.join(projectRoot, 'public', 'publication-reader.js');
const htmlPath = path.join(projectRoot, 'public', 'index.html');
const cssPath = path.join(projectRoot, 'public', 'styles.css');
const workbookPath = path.join(projectRoot, 'public', 'downloads', 'practical-ai-module-1-workbook.pdf');
const releasePath = path.join(projectRoot, 'public', 'release.json');
const gatewayScriptPath = path.join(projectRoot, 'public', 'gateway.js');
const gatewayArtworkPath = path.join(projectRoot, 'public', 'digital-literacy-gateway.png');
const reader = fs.readFileSync(readerPath, 'utf8');
const html = fs.readFileSync(htmlPath, 'utf8');
const css = fs.readFileSync(cssPath, 'utf8');
const failures = [];

const lessonPattern = /lessonPage\((\d+),\s*(\d+),\s*'([^']+)',\s*'([^']+)'[^\n]+?type:\s*'([^']+)'[^\n]+?id:\s*'([^']+)'[^\n]+?lessonNumber:\s*(\d+)/g;
const lessons = [...reader.matchAll(lessonPattern)].map((match) => ({
    number: Number(match[1]),
    week: Number(match[2]),
    title: match[3],
    image: match[4],
    activityType: match[5],
    activityId: match[6],
    activityLesson: Number(match[7])
}));

const expectedLessons = Array.from({ length: 12 }, (_, index) => index + 1);
const actualLessons = lessons.map((lesson) => lesson.number).sort((a, b) => a - b);
if (JSON.stringify(actualLessons) !== JSON.stringify(expectedLessons)) {
    failures.push(`Expected Module 1 lessons 1-12; found ${actualLessons.join(', ') || 'none'}.`);
}

const activityIds = new Set();
for (const lesson of lessons) {
    if (lesson.number !== lesson.activityLesson) failures.push(`Lesson ${lesson.number} activity points to Lesson ${lesson.activityLesson}.`);
    if (lesson.week !== Math.ceil(lesson.number / 3)) failures.push(`Lesson ${lesson.number} is assigned to Week ${lesson.week}.`);
    if (activityIds.has(lesson.activityId)) failures.push(`Duplicate lesson activity id: ${lesson.activityId}.`);
    activityIds.add(lesson.activityId);
    const imagePath = path.join(projectRoot, 'public', lesson.image.replace(/^\.\//, ''));
    if (!fs.existsSync(imagePath)) failures.push(`Missing lesson image: ${lesson.image}.`);
    if (lesson.activityType === 'guided-note' && !reader.includes(`'${lesson.activityId}': {`)) failures.push(`Missing guided activity configuration: ${lesson.activityId}.`);
    if (lesson.activityType === 'choice-check' && !reader.includes(`'${lesson.activityId}': {`)) failures.push(`Missing choice activity configuration: ${lesson.activityId}.`);
}

const requiredIds = [
    'learningGateway', 'learningGatewayContinue', 'learningGatewayReturn',
    'courseReader', 'publicationPages', 'publicationProgress', 'publicationToc',
    'publicationActivity', 'publicationActivityTitle', 'publicationActivityBody',
    'publicationImageViewer', 'publicationImageFull', 'publicationExport', 'publicationReset'
];
for (const id of requiredIds) {
    if (!html.includes(`id="${id}"`)) failures.push(`Missing reader markup id: ${id}.`);
}

const openBraces = (css.match(/\{/g) || []).length;
const closeBraces = (css.match(/\}/g) || []).length;
if (openBraces !== closeBraces) failures.push(`Stylesheet braces are unbalanced (${openBraces} open, ${closeBraces} close).`);
if (!fs.existsSync(workbookPath)) failures.push('Missing downloadable Module 1 workbook PDF.');
if (!fs.existsSync(releasePath)) failures.push('Missing release manifest.');
if (!fs.existsSync(gatewayScriptPath)) failures.push('Missing learning gateway behavior script.');
if (!fs.existsSync(gatewayArtworkPath)) failures.push('Missing learning gateway artwork.');
if (!html.includes('./downloads/practical-ai-module-1-workbook.pdf')) failures.push('Workbook is not linked from the learning hub.');

if (failures.length) {
    console.error(failures.map((failure) => `FAIL ${failure}`).join('\n'));
    process.exitCode = 1;
} else {
    console.log(`Publication check passed: ${lessons.length} Module 1 lessons, ${activityIds.size} unique lesson activities, and all artwork paths present.`);
}
