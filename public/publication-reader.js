const READER_STORAGE_KEY = 'cyberShieldPublicationReader';
const COURSE_PROGRESS_KEY = 'cyberShieldLearningProgress';

const lessonPage = (lessonNumber, week, title, image, caption, activity) => ({
    type: 'image',
    tag: `Module 1 | Week ${week} | Lesson ${lessonNumber}`,
    title,
    image,
    caption,
    activity
});

const weekDivider = (week, title, summary) => ({
    type: 'divider',
    tag: `Module 1 | Week ${week}`,
    title,
    subtitle: summary,
    content: `<div class="publication-module-map"><span>3 lessons</span><span>Beginner friendly</span><span>Practice included</span></div>`
});

const PUBLICATION_PAGES = [
    {
        type: 'cover',
        tag: 'Course cover',
        title: 'Practical AI for Everyday Life',
        subtitle: 'A digital coursebook for smarter tasks, safer habits, and everyday confidence.',
        image: './monthly-covers/2026-08.png'
    },
    {
        type: 'editorial',
        tag: 'Opening pages',
        title: 'Welcome to a practical kind of AI literacy',
        content: `
            <p class="publication-lead">Artificial intelligence is already part of ordinary life. This coursebook helps you understand it without hype, use it without guesswork, and slow down when accuracy or privacy matters.</p>
            <div class="publication-callout"><strong>Course promise</strong><p>Start small. Ask clearly. Review carefully. Verify what matters.</p></div>
            <p>You do not need programming experience, technical vocabulary, or a paid AI subscription. You only need a familiar device, one low-risk task, and a willingness to review the result.</p>`
    },
    {
        type: 'editorial',
        tag: 'Course mission',
        title: 'Build confidence without building overtrust',
        content: `
            <div class="publication-feature-list">
                <div><span>01</span><strong>Understand</strong><p>Recognize what AI does, where it appears, and why it can be wrong.</p></div>
                <div><span>02</span><strong>Use</strong><p>Apply AI to familiar writing, planning, organizing, and learning tasks.</p></div>
                <div><span>03</span><strong>Judge</strong><p>Protect privacy, verify claims, and keep responsibility for decisions.</p></div>
            </div>`
    },
    {
        type: 'pathway',
        tag: 'Your learning pathway',
        title: 'Three modules. Twelve weeks. Thirty-six lessons.',
        content: `
            <ol class="publication-pathway">
                <li class="is-current"><span>Module 1</span><strong>Understand AI</strong><small>Recognition and foundational literacy</small></li>
                <li><span>Module 2</span><strong>Use AI</strong><small>Practical application for everyday tasks</small></li>
                <li><span>Module 3</span><strong>Build Safe Habits</strong><small>Judgment, verification, and sustainable routines</small></li>
                <li><span>Final project</span><strong>Personal AI Playbook</strong><small>Your reusable prompts and review rules</small></li>
            </ol>`
    },
    {
        type: 'editorial',
        tag: 'Before you begin',
        title: 'One device and one reputable AI assistant are enough',
        content: `
            <div class="publication-two-column">
                <section><h3>Smartphone</h3><p>Use an official app or trusted browser. Voice input can reduce typing, but review dictated text before sending.</p></section>
                <section><h3>Desktop or laptop</h3><p>A larger screen makes comparison, long responses, and side-by-side verification easier.</p></section>
            </div>
            <div class="publication-callout"><strong>Choose one tool</strong><p>The course teaches transferable skills. Consistency is more useful than switching between several assistants.</p></div>`
    },
    {
        type: 'safety',
        tag: 'Privacy rules',
        title: 'Remove private information before you press Send',
        content: `
            <ul class="publication-checklist">
                <li>Never enter passwords or security codes.</li>
                <li>Remove identification and account numbers.</li>
                <li>Replace names, addresses, and client details with placeholders.</li>
                <li>Do not upload confidential work without authorization.</li>
                <li>Pause for health, legal, financial, safety, or eligibility decisions.</li>
            </ul>
            <p class="publication-warning">AI is an assistant. It is not a confidential vault, a final authority, or a replacement for qualified expertise.</p>`
    },
    {
        type: 'editorial',
        tag: 'Reader guide',
        title: 'How to use this coursebook',
        content: `
            <div class="publication-tool-grid">
                <div><strong>Turn pages</strong><p>Use the page edges, arrow buttons, keyboard arrows, or swipe.</p></div>
                <div><strong>Open activities</strong><p>Glowing activity tabs add practice without replacing the lesson page.</p></div>
                <div><strong>Save your place</strong><p>The reader remembers your page, bookmark, prompt, and notes on this device.</p></div>
                <div><strong>Use text mode</strong><p>The complete lesson index remains available behind the reader.</p></div>
            </div>
            <p class="publication-device-note">Progress is stored on this device. Clearing browser data or changing devices may remove it.</p>`
    },
    {
        type: 'divider',
        tag: 'Module 1 | Weeks 1-4',
        title: 'Understand AI',
        subtitle: 'Recognition and foundational digital literacy',
        content: `
            <p>Learn what AI is, where it appears, what it does well, where it fails, and how wording changes a response.</p>
            <div class="publication-module-map"><span>12 lessons</span><span>4 weeks</span><span>6-8 hours</span></div>
            <h3>Four-week route</h3><p>Start with recognition, add safe-use judgment, improve your instructions, and finish with one repeatable habit.</p>`
    },
    weekDivider(1, 'Meet AI in Everyday Life', 'Recognize AI, notice where it already appears, and choose a safe first task.'),
    lessonPage(1, 1, 'What Is AI?', './course-pages/module-1/week-1/lesson-1-what-is-ai.png', 'AI is a pattern-based digital assistant, not an all-knowing expert.', { type: 'guided-note', id: 'lesson-1-definition', label: 'Explain AI', lessonNumber: 1 }),
    lessonPage(2, 1, 'Where AI Already Appears', './course-pages/module-1/week-1/lesson-2-ai-everyday-life.png', 'Many familiar apps use AI quietly behind the scenes.', { type: 'guided-note', id: 'lesson-2-inventory', label: 'Build an Inventory', lessonNumber: 2 }),
    lessonPage(3, 1, 'First Easy Uses for Beginners', './course-pages/module-1/week-1/lesson-3-first-easy-uses.png', 'Begin with a familiar, low-risk task whose result is easy to review.', { type: 'guided-note', id: 'lesson-3-first-task', label: 'Choose a First Task', lessonNumber: 3 }),
    weekDivider(2, 'Benefits, Limits, and Safe Use', 'Balance usefulness with privacy, verification, and human judgment.'),
    lessonPage(4, 2, 'AI Benefits vs. Limitations', './course-pages/module-1/week-2/lesson-4-benefits-limitations.png', 'AI can save time and organize ideas, but it can also be wrong, incomplete, or biased.', { type: 'choice-check', id: 'lesson-4-benefits-limits', label: 'Benefits or Limits?', lessonNumber: 4 }),
    lessonPage(5, 2, 'Using AI Safely', './course-pages/module-1/week-2/lesson-5-using-ai-safely.png', 'Protect private information and verify important claims before acting.', { type: 'choice-check', id: 'lesson-5-safety-sort', label: 'Safety Check', lessonNumber: 5 }),
    lessonPage(6, 2, 'When to Use AI - and When to Slow Down', './course-pages/module-1/week-2/lesson-6-when-to-slow-down.png', 'Consequential advice, private data, and unsupported claims deserve a pause.', { type: 'choice-check', id: 'lesson-6-risk-sort', label: 'Use or Slow Down?', lessonNumber: 6 }),
    weekDivider(3, 'How AI Responds', 'Understand pattern learning, changing responses, and the structure of a clearer prompt.'),
    lessonPage(7, 3, 'How AI Learns in Simple Terms', './course-pages/module-1/week-3/lesson-7-how-ai-learns.png', 'AI learns patterns from examples. Prediction is not the same as human understanding.', { type: 'guided-note', id: 'lesson-7-analogy', label: 'Try an Analogy', lessonNumber: 7 }),
    lessonPage(8, 3, 'Why AI Responses Can Change', './course-pages/module-1/week-3/lesson-8-responses-change.png', 'Wording, context, requested format, and detail level all shape an AI response.', { type: 'guided-note', id: 'lesson-8-rewrite', label: 'Improve a Request', lessonNumber: 8 }),
    lessonPage(9, 3, 'Turn Vague Requests Into Better Prompts', './course-pages/module-1/week-3/lesson-9-better-prompts.png', 'Use Task + Context + Format + Limits to reduce guesswork.', { type: 'prompt-builder', id: 'lesson-9-prompt-builder', label: 'Build Your Prompt', lessonNumber: 9 }),
    {
        type: 'concepts',
        tag: 'Lesson 9 | Explore',
        title: 'The four parts of a strong prompt',
        content: `
            <div class="publication-concept-grid">
                <details open><summary>Task</summary><p>Say exactly what you want the AI to do. Begin with an action such as rewrite, summarize, compare, plan, or explain.</p></details>
                <details><summary>Context</summary><p>Add only the background needed to understand the situation, audience, and purpose. Use placeholders instead of private details.</p></details>
                <details><summary>Format</summary><p>Name the output you want: bullets, a short email, a checklist, a table, or a step-by-step explanation.</p></details>
                <details><summary>Limits</summary><p>Define length, tone, must-include details, exclusions, and what the AI should identify rather than invent.</p></details>
            </div>`
    },
    {
        type: 'demonstration',
        tag: 'Lesson 9 | Demonstration',
        title: 'Same task. Better instructions.',
        content: `
            <div class="publication-comparison">
                <section><span>Vague</span><p>Help me write an email.</p></section>
                <section><span>Better</span><p>Write a polite email to my landlord about a leaking sink.</p></section>
                <section class="is-strong"><span>Stronger</span><p>Write a polite email to my landlord about a leaking sink. Ask for a repair this week. Keep it under 120 words and sound professional.</p></section>
            </div>
            <div class="publication-callout"><strong>What changed?</strong><p>The stronger prompt adds audience, purpose, timing, length, and tone while keeping private details out.</p></div>`
    },
    {
        type: 'activity',
        tag: 'Lesson 9 | Practice',
        title: 'Build a prompt for one real task',
        content: `
            <p class="publication-lead">Choose a familiar, low-risk task. Add the four parts, review the combined prompt, and save it to this device.</p>
            <div class="publication-activity-preview"><span>Task</span><span>Context</span><span>Format</span><span>Limits</span></div>`,
        activity: { type: 'prompt-builder', id: 'lesson-9-prompt-builder', label: 'Open Prompt Builder', lessonNumber: 9 }
    },
    {
        type: 'activity',
        tag: 'Lesson 9 | Quick check',
        title: 'Check what you learned',
        content: `
            <p class="publication-lead">Answer three short questions about prompt quality, privacy, and verification. You can retry immediately.</p>
            <div class="publication-callout"><strong>Completion rule</strong><p>Answer all three correctly to mark this prototype activity complete.</p></div>`,
        activity: { type: 'quick-check', id: 'lesson-9-quick-check', label: 'Start Quick Check' }
    },
    {
        type: 'reflection',
        tag: 'Lesson 9 | Reflection',
        title: 'What will you try first?',
        content: `
            <p class="publication-lead">Name one task you would feel comfortable testing with AI this week. Keep it familiar, low-risk, and easy to review.</p>
            <div class="publication-callout"><strong>Reusable reminder</strong><p>Clear instructions improve usefulness. They do not guarantee accuracy.</p></div>`,
        activity: { type: 'reflection', id: 'lesson-9-reflection', label: 'Save a Private Note' }
    },
    weekDivider(4, 'Notice AI and Build One Habit', 'Recognize everyday AI, choose the benefit you need, and create a small repeatable routine.'),
    lessonPage(10, 4, 'AI in Everyday Tools You Already Use', './course-pages/module-1/week-4/lesson-10-ai-everyday-tools.png', 'Search, feeds, email, streaming, and shopping tools often use AI in the background.', { type: 'guided-note', id: 'lesson-10-app-audit', label: 'Audit an App', lessonNumber: 10 }),
    lessonPage(11, 4, 'The Benefits of AI', './course-pages/module-1/week-4/lesson-11-benefits-of-ai.png', 'Useful AI support can save time, reduce friction, organize information, and make learning easier.', { type: 'guided-note', id: 'lesson-11-benefit-priority', label: 'Choose a Benefit', lessonNumber: 11 }),
    lessonPage(12, 4, 'Building Your First AI Habit', './course-pages/module-1/week-4/lesson-12-first-ai-habit.png', 'Pick one task, use one clear prompt, review, refine, and repeat.', { type: 'guided-note', id: 'lesson-12-habit-plan', label: 'Build a Habit', lessonNumber: 12 }),
    {
        type: 'closing',
        tag: 'Module 1 review',
        title: 'You understand the foundations',
        content: `
            <p class="publication-lead">Complete each lesson's short activity to illuminate all twelve Module 1 lessons and unlock Module 2.</p>
            <ul class="publication-checklist"><li>Recognize AI in familiar tools.</li><li>Balance benefits with limitations.</li><li>Protect privacy and verify important claims.</li><li>Write clearer prompts.</li><li>Build one low-risk AI habit.</li></ul>
            <p class="publication-device-note">Your completion record, prompts, and private notes remain stored in this browser on this device.</p>`,
        activity: { type: 'module-review', id: 'module-1-review', label: 'Review Progress' }
    }
];

const GUIDED_ACTIVITIES = {
    'lesson-1-definition': {
        title: 'Explain AI in Plain Language',
        question: 'In one or two sentences, how would you explain AI to a friend who has never used it?',
        placeholder: 'AI is a digital tool that...',
        helper: 'Include patterns or predictions, and avoid describing AI as magic or an all-knowing expert.'
    },
    'lesson-2-inventory': {
        title: 'Build an AI Around Me Inventory',
        question: 'List three apps or services you use and the feature that may be powered by AI.',
        placeholder: '1. Email - spam filtering\n2. Maps - route suggestions\n3. ...',
        helper: 'You might consider predictive text, recommendations, photo tools, search, maps, or smart-home features.'
    },
    'lesson-3-first-task': {
        title: 'Choose a Safe First Task',
        question: 'Name one familiar, low-risk task you could try and explain how you would review the result.',
        placeholder: 'I would ask AI to... I would review it by...',
        helper: 'Good first tasks include summarizing non-private notes, rewriting a message, brainstorming, or making a checklist.'
    },
    'lesson-7-analogy': {
        title: 'Try a Pattern-Learning Analogy',
        question: 'Complete this thought: AI learning is a little like..., but it is different because...',
        placeholder: 'AI learning is a little like noticing patterns in..., but...',
        helper: 'The goal is to distinguish pattern prediction from human experience, intention, or understanding.'
    },
    'lesson-8-rewrite': {
        title: 'Improve a Vague Request',
        question: 'Rewrite "Help me plan" by adding the purpose, useful context, desired format, and at least one limit.',
        placeholder: 'Create a... The plan is for... Present it as... Keep it...',
        helper: 'Do not add private information. Clearer wording improves relevance, not guaranteed accuracy.'
    },
    'lesson-10-app-audit': {
        title: 'Audit One Familiar App',
        question: 'Name one app, its likely AI-powered feature, its benefit, and one privacy or personalization setting to review.',
        placeholder: 'App: ...\nFeature: ...\nBenefit: ...\nSetting to review: ...',
        helper: 'Consider location, microphone, photos, history, ad personalization, or recommendation controls.'
    },
    'lesson-11-benefit-priority': {
        title: 'Choose the Benefit You Need',
        question: 'Which benefit would help you most right now: saving time, writing, organizing, generating ideas, or learning? Name one task.',
        placeholder: 'The benefit I need most is... It could help me...',
        helper: 'Choose a small, realistic improvement rather than expecting a perfect or fully automated result.'
    },
    'lesson-12-habit-plan': {
        title: 'Build Your First AI Habit',
        question: 'Create a one-week plan: name the task, your starter prompt, when you will use it, and what you will double-check.',
        placeholder: 'Task: ...\nStarter prompt: ...\nWhen: ...\nI will double-check: ...',
        helper: 'Keep the habit low-risk, repeatable, and easy to review. You can change or stop it if it is not helpful.'
    }
};

const CHOICE_ACTIVITIES = {
    'lesson-4-benefits-limits': {
        title: 'Benefits or Limitations?',
        questions: [
            { question: 'AI can turn rough notes into a checklist.', options: ['Benefit', 'Limitation'], answer: 0 },
            { question: 'AI may invent a source that sounds believable.', options: ['Benefit', 'Limitation'], answer: 1 },
            { question: 'AI can explain a topic in simpler language.', options: ['Benefit', 'Limitation'], answer: 0 }
        ]
    },
    'lesson-5-safety-sort': {
        title: 'Safe, Edit First, or Do Not Share?',
        questions: [
            { question: 'Brainstorm five general dinner ideas.', options: ['Safe', 'Edit First', 'Do Not Share'], answer: 0 },
            { question: 'Organize a budget that still contains bank account numbers.', options: ['Safe', 'Edit First', 'Do Not Share'], answer: 1 },
            { question: 'Here is my password. Tell me whether it is strong.', options: ['Safe', 'Edit First', 'Do Not Share'], answer: 2 }
        ]
    },
    'lesson-6-risk-sort': {
        title: 'Use AI or Slow Down?',
        questions: [
            { question: 'Turn non-private meeting notes into a checklist.', options: ['Use normally and review', 'Slow down and verify'], answer: 0 },
            { question: 'Decide whether to change a prescription dosage.', options: ['Use normally and review', 'Slow down and seek qualified help'], answer: 1 },
            { question: 'Confirm an application deadline that affects eligibility.', options: ['Trust the first answer', 'Verify with the official source'], answer: 1 }
        ]
    }
};

const MODULE_ONE_TITLES = [...new Map(PUBLICATION_PAGES
    .filter((page) => page.activity?.lessonNumber)
    .sort((a, b) => a.activity.lessonNumber - b.activity.lessonNumber)
    .map((page) => [page.activity.lessonNumber, { number: page.activity.lessonNumber, title: page.title }])).values()];

const readerDialog = document.getElementById('courseReader');
const activityDialog = document.getElementById('publicationActivity');
const readerPages = document.getElementById('publicationPages');
const readerProgress = document.getElementById('publicationProgress');
const readerToc = document.getElementById('publicationToc');
const readerTocList = document.getElementById('publicationTocList');
const bookmarkButton = document.getElementById('publicationBookmark');
const activityTitle = document.getElementById('publicationActivityTitle');
const activityBody = document.getElementById('publicationActivityBody');
const imageDialog = document.getElementById('publicationImageViewer');
const imageDialogTitle = document.getElementById('publicationImageTitle');
const imageDialogImage = document.getElementById('publicationImageFull');

const readReaderState = () => {
    try {
        const saved = JSON.parse(localStorage.getItem(READER_STORAGE_KEY) || '{}');
        return {
            page: Math.min(Math.max(Number(saved.page) || 0, 0), PUBLICATION_PAGES.length - 1),
            bookmark: Number.isInteger(saved.bookmark) ? saved.bookmark : null,
            textScale: Math.min(Math.max(Number(saved.textScale) || 1, 0.9), 1.2),
            completedActivities: new Set(Array.isArray(saved.completedActivities) ? saved.completedActivities : []),
            prompt: saved.prompt || {},
            reflection: saved.reflection || '',
            responses: saved.responses && typeof saved.responses === 'object' ? saved.responses : {}
        };
    } catch {
        return { page: 0, bookmark: null, textScale: 1, completedActivities: new Set(), prompt: {}, reflection: '', responses: {} };
    }
};

const readerState = readReaderState();

const saveReaderState = () => {
    try {
        localStorage.setItem(READER_STORAGE_KEY, JSON.stringify({
            page: readerState.page,
            bookmark: readerState.bookmark,
            textScale: readerState.textScale,
            completedActivities: [...readerState.completedActivities],
            prompt: readerState.prompt,
            reflection: readerState.reflection,
            responses: readerState.responses
        }));
    } catch {
        // The reader remains usable when browser storage is unavailable.
    }
};

const isMobileReader = () => window.matchMedia('(max-width: 760px)').matches;
const spreadStart = (pageIndex) => pageIndex === 0 || isMobileReader() ? pageIndex : (pageIndex % 2 === 0 ? pageIndex - 1 : pageIndex);

const pageIndicesForView = () => {
    if (isMobileReader() || readerState.page === 0) return [readerState.page];
    const first = spreadStart(readerState.page);
    return [first, first + 1].filter((index) => index < PUBLICATION_PAGES.length);
};

const createPage = (page, index) => {
    const article = document.createElement('article');
    article.className = `publication-page publication-page-${page.type}`;
    article.dataset.page = String(index);

    if (page.image) {
        const image = document.createElement('img');
        image.src = page.image;
        image.alt = page.title;
        image.className = 'publication-page-image';
        image.loading = 'eager';
        image.tabIndex = 0;
        image.setAttribute('role', 'button');
        image.setAttribute('aria-label', `Enlarge ${page.title}`);
        image.addEventListener('click', () => openImageViewer(page));
        image.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                openImageViewer(page);
            }
        });
        article.append(image);

        const enlargeButton = document.createElement('button');
        enlargeButton.type = 'button';
        enlargeButton.className = 'publication-enlarge-button';
        enlargeButton.textContent = 'Enlarge Page';
        enlargeButton.addEventListener('click', () => openImageViewer(page));
        article.append(enlargeButton);
    }

    if (page.type !== 'cover' || !page.image) {
        const copy = document.createElement('div');
        copy.className = 'publication-page-copy';
        const tag = document.createElement('p');
        tag.className = 'publication-page-kicker';
        tag.textContent = page.tag;
        const heading = document.createElement('h2');
        heading.textContent = page.title;
        copy.append(tag, heading);
        if (page.subtitle) {
            const subtitle = document.createElement('p');
            subtitle.className = 'publication-page-subtitle';
            subtitle.textContent = page.subtitle;
            copy.append(subtitle);
        }
        if (page.content) {
            const content = document.createElement('div');
            content.className = 'publication-page-content';
            content.innerHTML = page.content;
            copy.append(content);
        }
        if (page.caption) {
            const caption = document.createElement('p');
            caption.className = 'publication-page-caption';
            caption.textContent = page.caption;
            copy.append(caption);
        }
        article.append(copy);
    } else {
        const coverCopy = document.createElement('div');
        coverCopy.className = 'publication-cover-copy';
        coverCopy.innerHTML = `<p>${page.tag}</p><h2>${page.title}</h2><span>${page.subtitle}</span>`;
        article.append(coverCopy);
    }

    if (page.activity) {
        const activityButton = document.createElement('button');
        activityButton.type = 'button';
        activityButton.className = 'publication-activity-tab';
        activityButton.dataset.activity = page.activity.id;
        activityButton.innerHTML = `<span>${readerState.completedActivities.has(page.activity.id) ? 'Completed' : 'Interactive'}</span><strong>${page.activity.label}</strong>`;
        activityButton.addEventListener('click', () => openActivity(page.activity));
        article.append(activityButton);
    }

    const pageNumber = document.createElement('span');
    pageNumber.className = 'publication-page-number';
    pageNumber.textContent = index === 0 ? 'Cover' : String(index);
    article.append(pageNumber);
    return article;
};

const updateReaderControls = () => {
    const indices = pageIndicesForView();
    document.getElementById('publicationPrev').disabled = readerState.page === 0;
    document.getElementById('publicationNext').disabled = indices.at(-1) >= PUBLICATION_PAGES.length - 1;
    readerProgress.textContent = indices.length === 1
        ? `${indices[0] === 0 ? 'Cover' : `Page ${indices[0]}`} of ${PUBLICATION_PAGES.length - 1}`
        : `Pages ${indices[0]}-${indices[1]} of ${PUBLICATION_PAGES.length - 1}`;
    const bookmarked = readerState.bookmark !== null && indices.includes(readerState.bookmark);
    bookmarkButton.classList.toggle('is-active', bookmarked);
    bookmarkButton.setAttribute('aria-pressed', String(bookmarked));
    bookmarkButton.textContent = bookmarked ? 'Bookmarked' : 'Bookmark';
};

const renderReader = () => {
    readerState.page = spreadStart(readerState.page);
    const indices = pageIndicesForView();
    readerPages.replaceChildren(...indices.map((index) => createPage(PUBLICATION_PAGES[index], index)));
    readerPages.querySelectorAll('.publication-page').forEach((page) => {
        page.scrollTop = 0;
        page.scrollLeft = 0;
    });
    readerPages.classList.toggle('is-single-page', indices.length === 1);
    readerPages.style.setProperty('--publication-text-scale', readerState.textScale);
    updateReaderControls();
    saveReaderState();
    readerTocList.querySelectorAll('button').forEach((button) => {
        button.classList.toggle('is-current', indices.includes(Number(button.dataset.page)));
    });
};

const goToPage = (pageIndex) => {
    readerState.page = Math.min(Math.max(pageIndex, 0), PUBLICATION_PAGES.length - 1);
    renderReader();
};

const turnPage = (direction) => {
    if (isMobileReader()) goToPage(readerState.page + direction);
    else if (readerState.page === 0 && direction > 0) goToPage(1);
    else if (readerState.page === 1 && direction < 0) goToPage(0);
    else goToPage(readerState.page + (direction * 2));
};

const buildToc = () => {
    readerTocList.replaceChildren(...PUBLICATION_PAGES.map((page, index) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.page = String(index);
        button.innerHTML = `<span>${index === 0 ? 'Cover' : String(index).padStart(2, '0')}</span><strong>${page.title}</strong>`;
        button.addEventListener('click', () => {
            goToPage(index);
            readerToc.classList.remove('is-open');
        });
        return button;
    }));
};

const openReader = (mode = 'start') => {
    if (mode === 'start') readerState.page = 0;
    else if (mode === 'bookmark' && readerState.bookmark !== null) readerState.page = readerState.bookmark;
    if (!readerDialog.open) readerDialog.showModal();
    document.body.classList.add('publication-open');
    renderReader();
};

const closeReader = () => {
    saveReaderState();
    if (activityDialog.open) activityDialog.close();
    if (imageDialog.open) imageDialog.close();
    readerToc.classList.remove('is-open');
    if (readerDialog.open) readerDialog.close();
    document.body.classList.remove('publication-open');
};

const completeActivity = (activityId, lessonNumber = null) => {
    readerState.completedActivities.add(activityId);
    saveReaderState();
    if (Number.isInteger(lessonNumber)) {
        try {
            const courseProgress = new Set(JSON.parse(localStorage.getItem(COURSE_PROGRESS_KEY) || '[]'));
            courseProgress.add(lessonNumber);
            localStorage.setItem(COURSE_PROGRESS_KEY, JSON.stringify([...courseProgress].sort((a, b) => a - b)));
        } catch {
            // Activity completion remains in reader state if course progress cannot be saved.
        }
        window.dispatchEvent(new CustomEvent('cybershield:lesson-complete', { detail: { lessonNumber } }));
    }
    renderReader();
};

const combinedPrompt = (values) => {
    const parts = [];
    if (values.task) parts.push(values.task.trim().replace(/[.]+$/, ''));
    if (values.context) parts.push(`The situation is: ${values.context.trim().replace(/[.]+$/, '')}`);
    if (values.format) parts.push(`Present the answer as ${values.format.trim().replace(/[.]+$/, '')}`);
    if (values.limits) parts.push(`Follow these limits: ${values.limits.trim().replace(/[.]+$/, '')}`);
    return parts.length ? `${parts.join('. ')}.` : 'Add your task, context, format, and limits to build a prompt.';
};

const renderPromptBuilder = (activity) => {
    activityTitle.textContent = 'Build Your Prompt';
    activityBody.innerHTML = `
        <form class="publication-prompt-form" id="publicationPromptForm">
            <label><span>Task</span><textarea name="task" rows="2" placeholder="What should the AI do?"></textarea></label>
            <label><span>Context</span><textarea name="context" rows="2" placeholder="What background does it need?"></textarea></label>
            <label><span>Format</span><textarea name="format" rows="2" placeholder="Bullets, email, checklist, table..."></textarea></label>
            <label><span>Limits</span><textarea name="limits" rows="2" placeholder="Tone, length, must-include details..."></textarea></label>
            <div class="publication-prompt-output"><span>Your combined prompt</span><p id="publicationPromptOutput"></p></div>
            <p class="publication-activity-status" id="publicationPromptStatus" aria-live="polite"></p>
            <div class="publication-activity-actions">
                <button type="button" class="secondary" id="publicationCopyPrompt">Copy Prompt</button>
                <button type="submit" class="primary">Save Prompt</button>
            </div>
        </form>`;
    const form = document.getElementById('publicationPromptForm');
    const output = document.getElementById('publicationPromptOutput');
    const status = document.getElementById('publicationPromptStatus');
    [...form.elements].forEach((field) => {
        if (field.name && readerState.prompt[field.name]) field.value = readerState.prompt[field.name];
    });
    const values = () => Object.fromEntries(new FormData(form).entries());
    const refresh = () => { output.textContent = combinedPrompt(values()); };
    form.addEventListener('input', refresh);
    form.addEventListener('submit', (event) => {
        event.preventDefault();
        readerState.prompt = values();
        completeActivity(activity.id, activity.lessonNumber);
        status.textContent = 'Prompt saved on this device and activity marked complete.';
    });
    document.getElementById('publicationCopyPrompt').addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(combinedPrompt(values()));
            status.textContent = 'Prompt copied.';
        } catch {
            status.textContent = 'Copy was unavailable. Select the combined prompt and copy it manually.';
        }
    });
    refresh();
};

const QUICK_CHECK = [
    { question: 'Which prompt gives the clearest instruction?', options: ['Help me write something.', 'Write a polite 100-word email asking my landlord to repair a leaking sink this week.', 'Tell me about email.'], answer: 1 },
    { question: 'What should be removed before using a public AI assistant?', options: ['The requested tone', 'A desired bullet format', 'A banking password'], answer: 2 },
    { question: 'Does a detailed prompt guarantee a factual answer?', options: ['Yes', 'No - important claims still require verification'], answer: 1 }
];

const renderQuickCheck = (activity) => {
    activityTitle.textContent = 'Lesson 9 Quick Check';
    activityBody.innerHTML = `<form id="publicationQuiz" class="publication-quiz">${QUICK_CHECK.map((item, questionIndex) => `
        <fieldset><legend>${questionIndex + 1}. ${item.question}</legend>${item.options.map((option, optionIndex) => `
            <label><input type="radio" name="question-${questionIndex}" value="${optionIndex}"><span>${option}</span></label>`).join('')}</fieldset>`).join('')}
        <p class="publication-activity-status" id="publicationQuizStatus" aria-live="polite"></p>
        <div class="publication-activity-actions"><button type="submit" class="primary">Check Answers</button></div></form>`;
    const quiz = document.getElementById('publicationQuiz');
    const status = document.getElementById('publicationQuizStatus');
    quiz.addEventListener('submit', (event) => {
        event.preventDefault();
        const data = new FormData(quiz);
        const score = QUICK_CHECK.reduce((total, item, index) => total + (Number(data.get(`question-${index}`)) === item.answer ? 1 : 0), 0);
        if (score === QUICK_CHECK.length) {
            completeActivity(activity.id, activity.lessonNumber);
            status.textContent = '3 of 3 correct. Quick check complete.';
            status.className = 'publication-activity-status is-success';
        } else {
            status.textContent = `${score} of 3 correct. Review the lesson and try again.`;
            status.className = 'publication-activity-status is-review';
        }
    });
};

const renderReflection = (activity) => {
    activityTitle.textContent = 'Private Reflection';
    activityBody.innerHTML = `
        <form id="publicationReflection" class="publication-reflection-form">
            <label><span>What is one familiar, low-risk task you would try with AI?</span><textarea name="reflection" rows="7" placeholder="My first task would be..."></textarea></label>
            <p class="publication-device-note">This note stays in this browser on this device.</p>
            <p class="publication-activity-status" id="publicationReflectionStatus" aria-live="polite"></p>
            <div class="publication-activity-actions"><button type="submit" class="primary">Save Reflection</button></div>
        </form>`;
    const form = document.getElementById('publicationReflection');
    const field = form.elements.reflection;
    const status = document.getElementById('publicationReflectionStatus');
    field.value = readerState.reflection;
    form.addEventListener('submit', (event) => {
        event.preventDefault();
        readerState.reflection = field.value.trim();
        completeActivity(activity.id, activity.lessonNumber);
        status.textContent = 'Reflection saved on this device.';
    });
};

const renderGuidedNote = (activity) => {
    const guide = GUIDED_ACTIVITIES[activity.id];
    activityTitle.textContent = guide.title;
    activityBody.innerHTML = `
        <form id="publicationGuidedNote" class="publication-reflection-form">
            <label><span>${guide.question}</span><textarea name="response" rows="8" placeholder="${guide.placeholder}"></textarea></label>
            <div class="publication-callout"><strong>Helpful direction</strong><p>${guide.helper}</p></div>
            <p class="publication-device-note">Your response stays in this browser on this device.</p>
            <p class="publication-activity-status" id="publicationGuidedStatus" aria-live="polite"></p>
            <div class="publication-activity-actions"><button type="submit" class="primary">Save and Complete Lesson</button></div>
        </form>`;
    const form = document.getElementById('publicationGuidedNote');
    const field = form.elements.response;
    const status = document.getElementById('publicationGuidedStatus');
    field.value = readerState.responses[activity.id] || '';
    form.addEventListener('submit', (event) => {
        event.preventDefault();
        const response = field.value.trim();
        if (response.length < 12) {
            status.textContent = 'Add a little more detail before marking this lesson complete.';
            status.className = 'publication-activity-status is-review';
            return;
        }
        readerState.responses[activity.id] = response;
        completeActivity(activity.id, activity.lessonNumber);
        status.textContent = `Lesson ${activity.lessonNumber} saved and marked complete.`;
        status.className = 'publication-activity-status is-success';
    });
};

const renderChoiceCheck = (activity) => {
    const check = CHOICE_ACTIVITIES[activity.id];
    activityTitle.textContent = check.title;
    activityBody.innerHTML = `<form id="publicationLessonCheck" class="publication-quiz">${check.questions.map((item, questionIndex) => `
        <fieldset><legend>${questionIndex + 1}. ${item.question}</legend>${item.options.map((option, optionIndex) => `
            <label><input type="radio" name="question-${questionIndex}" value="${optionIndex}"><span>${option}</span></label>`).join('')}</fieldset>`).join('')}
        <p class="publication-activity-status" id="publicationLessonCheckStatus" aria-live="polite"></p>
        <div class="publication-activity-actions"><button type="submit" class="primary">Check Answers</button></div></form>`;
    const form = document.getElementById('publicationLessonCheck');
    const status = document.getElementById('publicationLessonCheckStatus');
    form.addEventListener('submit', (event) => {
        event.preventDefault();
        const data = new FormData(form);
        const score = check.questions.reduce((total, item, index) => total + (Number(data.get(`question-${index}`)) === item.answer ? 1 : 0), 0);
        if (score === check.questions.length) {
            completeActivity(activity.id, activity.lessonNumber);
            status.textContent = `${score} of ${check.questions.length} correct. Lesson ${activity.lessonNumber} complete.`;
            status.className = 'publication-activity-status is-success';
        } else {
            status.textContent = `${score} of ${check.questions.length} correct. Review the page and try again.`;
            status.className = 'publication-activity-status is-review';
        }
    });
};

const readCourseProgress = () => {
    try {
        return new Set(JSON.parse(localStorage.getItem(COURSE_PROGRESS_KEY) || '[]').map(Number));
    } catch {
        return new Set();
    }
};

const openImageViewer = (page) => {
    imageDialogTitle.textContent = page.title;
    imageDialogImage.src = page.image;
    imageDialogImage.alt = page.title;
    if (!imageDialog.open) imageDialog.showModal();
};

const resetPublicationProgress = () => {
    const approved = window.confirm('Reset all course progress on this device? This removes completed lessons, bookmarks, saved prompts, activity responses, and private reflections. This cannot be undone.');
    if (!approved) return;

    try {
        localStorage.removeItem(READER_STORAGE_KEY);
        localStorage.removeItem(COURSE_PROGRESS_KEY);
    } catch {
        // Continue resetting the in-memory state if browser storage is unavailable.
    }

    readerState.page = 0;
    readerState.bookmark = null;
    readerState.textScale = 1;
    readerState.completedActivities.clear();
    readerState.prompt = {};
    readerState.reflection = '';
    readerState.responses = {};
    window.dispatchEvent(new CustomEvent('cybershield:progress-reset'));
    renderReader();
    window.alert('Course progress has been reset on this device.');
};

const exportProgressSummary = () => {
    const progress = readCourseProgress();
    const lines = [
        'PRACTICAL AI FOR EVERYDAY LIFE',
        'Module 1 Progress Summary',
        `Exported: ${new Date().toLocaleString()}`,
        '',
        `${MODULE_ONE_TITLES.filter((lesson) => progress.has(lesson.number)).length} of ${MODULE_ONE_TITLES.length} lessons complete`,
        ''
    ];

    MODULE_ONE_TITLES.forEach((lesson) => {
        lines.push(`${progress.has(lesson.number) ? '[COMPLETE]' : '[NOT COMPLETE]'} Lesson ${lesson.number}: ${lesson.title}`);
    });
    lines.push('', 'Private notes, prompts, and activity responses are intentionally excluded from this export.');

    const download = document.createElement('a');
    download.href = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' }));
    download.download = 'practical-ai-module-1-progress.txt';
    document.body.append(download);
    download.click();
    download.remove();
    setTimeout(() => URL.revokeObjectURL(download.href), 0);
};

const renderModuleReview = () => {
    const progress = readCourseProgress();
    const completedCount = MODULE_ONE_TITLES.filter((lesson) => progress.has(lesson.number)).length;
    const moduleComplete = completedCount === MODULE_ONE_TITLES.length;
    activityTitle.textContent = 'Module 1 Progress';
    activityBody.innerHTML = `
        <div class="publication-module-review">
            <div class="publication-module-review-summary ${moduleComplete ? 'is-complete' : ''}">
                <span>${completedCount} of ${MODULE_ONE_TITLES.length} lessons complete</span>
                <strong>${moduleComplete ? 'Module 2 is unlocked' : 'Complete each lesson activity to continue'}</strong>
            </div>
            <ol>${MODULE_ONE_TITLES.map((lesson) => `<li class="${progress.has(lesson.number) ? 'is-complete' : ''}"><span>${progress.has(lesson.number) ? '\u2713' : String(lesson.number).padStart(2, '0')}</span><p><strong>Lesson ${lesson.number}</strong>${lesson.title}</p></li>`).join('')}</ol>
            <p class="publication-device-note">You can also mark a lesson complete from the accessible text index. Module 2 stays locked until all twelve lessons are complete.</p>
        </div>`;
};

function openActivity(activity) {
    if (activity.type === 'prompt-builder') renderPromptBuilder(activity);
    else if (activity.type === 'quick-check') renderQuickCheck(activity);
    else if (activity.type === 'guided-note') renderGuidedNote(activity);
    else if (activity.type === 'choice-check') renderChoiceCheck(activity);
    else if (activity.type === 'module-review') renderModuleReview();
    else renderReflection(activity);
    if (!activityDialog.open) activityDialog.showModal();
}

document.querySelectorAll('[data-open-course]').forEach((button) => {
    button.addEventListener('click', (event) => {
        event.preventDefault();
        openReader(button.dataset.openCourse || 'start');
    });
});
document.getElementById('publicationClose').addEventListener('click', closeReader);
document.getElementById('publicationPrev').addEventListener('click', () => turnPage(-1));
document.getElementById('publicationNext').addEventListener('click', () => turnPage(1));
document.getElementById('publicationContents').addEventListener('click', () => readerToc.classList.toggle('is-open'));
document.getElementById('publicationTocClose').addEventListener('click', () => readerToc.classList.remove('is-open'));
bookmarkButton.addEventListener('click', () => {
    readerState.bookmark = readerState.bookmark === readerState.page ? null : readerState.page;
    renderReader();
});
document.getElementById('publicationTextSize').addEventListener('click', () => {
    readerState.textScale = readerState.textScale >= 1.2 ? 0.9 : Number((readerState.textScale + 0.1).toFixed(1));
    renderReader();
});
document.getElementById('publicationExport').addEventListener('click', exportProgressSummary);
document.getElementById('publicationReset').addEventListener('click', resetPublicationProgress);
document.getElementById('publicationActivityClose').addEventListener('click', () => activityDialog.close());
document.getElementById('publicationImageClose').addEventListener('click', () => imageDialog.close());
readerDialog.addEventListener('cancel', (event) => { event.preventDefault(); closeReader(); });
activityDialog.addEventListener('cancel', (event) => { event.preventDefault(); activityDialog.close(); });
imageDialog.addEventListener('cancel', (event) => { event.preventDefault(); imageDialog.close(); });

let touchStart = null;
readerPages.addEventListener('touchstart', (event) => {
    if (event.changedTouches.length !== 1) {
        touchStart = null;
        return;
    }
    touchStart = {
        x: event.changedTouches[0].clientX,
        y: event.changedTouches[0].clientY
    };
}, { passive: true });
readerPages.addEventListener('touchend', (event) => {
    if (!touchStart || !event.changedTouches.length) return;
    const distanceX = event.changedTouches[0].clientX - touchStart.x;
    const distanceY = event.changedTouches[0].clientY - touchStart.y;
    touchStart = null;
    if (Math.abs(distanceX) > 60 && Math.abs(distanceX) > Math.abs(distanceY) * 1.25) {
        turnPage(distanceX < 0 ? 1 : -1);
    }
}, { passive: true });
readerPages.addEventListener('touchcancel', () => { touchStart = null; }, { passive: true });
window.addEventListener('keydown', (event) => {
    if (!readerDialog.open || activityDialog.open || imageDialog.open || ['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName)) return;
    if (event.key === 'ArrowRight') turnPage(1);
    if (event.key === 'ArrowLeft') turnPage(-1);
});
let readerWasMobile = isMobileReader();
window.addEventListener('resize', () => {
    const readerIsMobile = isMobileReader();
    if (readerDialog.open && readerIsMobile !== readerWasMobile) renderReader();
    readerWasMobile = readerIsMobile;
});
readerDialog.addEventListener('close', () => {
    readerToc.classList.remove('is-open');
    document.body.classList.remove('publication-open');
});

buildToc();
