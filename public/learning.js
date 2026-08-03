const LESSONS = [
    {
        number: 1, module: 1, week: 1, title: 'What Is AI?',
        objectives: ['Describe AI as a pattern-based digital tool.', 'Explain why AI is not magic or an all-knowing expert.'],
        points: ['AI recognizes patterns and produces likely responses.', 'AI can sound confident while being wrong.'],
        activity: 'Compare three definitions of AI and identify the clearest, most accurate beginner-friendly version.',
        prompt: 'Explain artificial intelligence in plain language for a beginner.',
        safety: 'Treat a confident answer as a draft to review, not proof that it is correct.'
    },
    {
        number: 2, module: 1, week: 1, title: 'Where AI Already Appears',
        objectives: ['Identify common AI-supported services.', 'Recognize background personalization.'],
        points: ['Predictive text, spam filters, maps, recommendations, voice assistants, and photo tools may use AI.', 'Convenience often depends on collected behavior and preferences.'],
        activity: 'Complete an AI Around Me inventory for five apps or services you use.',
        prompt: 'Give me examples of AI already used in everyday life.',
        safety: 'Review privacy and personalization controls in the services you use.'
    },
    {
        number: 3, module: 1, week: 1, title: 'First Easy Uses for Beginners',
        objectives: ['Select a low-risk first task.', 'Use one beginner prompt and review the result.'],
        points: ['Good first uses include summarizing, rewriting, brainstorming, planning, and learning.', 'Start with familiar tasks whose results are easy to check.'],
        activity: 'Choose one simple task, create a result, then revise it into a final version.',
        prompt: 'Help me use AI for this simple task: [insert task].',
        safety: 'Do not use a first exercise for medical, legal, financial, or other high-stakes decisions.'
    },
    {
        number: 4, module: 1, week: 2, title: 'AI Benefits vs. Limitations',
        objectives: ['Describe four strengths and four limitations.', 'Avoid treating AI as an authority.'],
        points: ['AI can help with speed, structure, explanations, and drafts.', 'Weaknesses include errors, bias, omissions, and invented sources.'],
        activity: 'Sort example statements into benefits or limitations and explain each choice.',
        prompt: 'List three benefits and three limitations of AI for everyday tasks.',
        safety: 'Use AI to support your thinking, not replace responsibility or judgment.'
    },
    {
        number: 5, module: 1, week: 2, title: 'Using AI Safely',
        objectives: ['Identify sensitive information.', 'Apply four safe-use habits.'],
        points: ['Protect privacy, fact-check, give clear instructions, and treat AI as a helper.', 'Passwords, IDs, payment details, and confidential records do not belong in prompts.'],
        activity: 'Classify sample prompts as Safe, Edit First, or Do Not Share.',
        prompt: 'Review this text and identify private information that should be removed.',
        safety: 'Replace names, addresses, account numbers, and other identifiers with neutral placeholders.'
    },
    {
        number: 6, module: 1, week: 2, title: 'When to Use AI and When to Slow Down',
        objectives: ['Distinguish low-risk tasks from consequential guidance.', 'Identify situations requiring an authoritative source or professional.'],
        points: ['Drafting and organizing are generally easier to review.', 'Health, rights, money, safety, and deadlines require extra caution.'],
        activity: 'Classify everyday scenarios by risk and identify what should be verified.',
        prompt: 'Help me decide whether this task is a good fit for AI.',
        safety: 'Seek authoritative or professional guidance when a wrong answer could cause harm.'
    },
    {
        number: 7, module: 1, week: 3, title: 'How AI Learns in Simple Terms',
        objectives: ['Explain training data and pattern recognition.', 'Recognize that prediction is not human thinking.'],
        points: ['AI systems learn patterns from data and use those patterns to make predictions.', 'Biased or poor-quality data can affect the output.'],
        activity: 'Use a word-prediction exercise to demonstrate pattern-based completion.',
        prompt: 'Explain how AI learns using a simple everyday analogy.',
        safety: 'Avoid assuming that an AI experiences, understands, or intends things like a person.'
    },
    {
        number: 8, module: 1, week: 3, title: 'Why AI Responses Can Change',
        objectives: ['Explain why wording and context matter.', 'Compare vague and specific prompts.'],
        points: ['Wording, context, format, and detail shape a response.', 'The same task may produce different outputs on different attempts.'],
        activity: 'Compare a vague email request with a detailed version that includes audience, tone, and purpose.',
        prompt: 'Show me how wording changes the quality of an AI answer.',
        safety: 'A different or polished answer is not automatically a more accurate answer.'
    },
    {
        number: 9, module: 1, week: 3, title: 'Turn Vague Requests Into Better Prompts',
        objectives: ['Use Task + Context + Format + Limits.', 'Improve a result with follow-up questions.'],
        points: ['Clear prompts reduce guesswork.', 'A useful prompt describes the outcome and important boundaries.'],
        activity: 'Improve three vague requests using the four-part prompt formula.',
        prompt: 'Turn this rough request into a clearer AI prompt: [paste request].',
        safety: 'Prompt quality can improve relevance, but it never guarantees truth.'
    },
    {
        number: 10, module: 1, week: 4, title: 'AI in Everyday Tools',
        objectives: ['Identify AI features in familiar apps.', 'Recognize both convenience and influence.'],
        points: ['Search, feeds, spam filters, streaming, shopping, and smart devices commonly use AI.', 'Recommendation systems can shape what people see and choose.'],
        activity: 'Audit three apps: identify the feature, benefit, likely data used, and settings to review.',
        prompt: 'Help me identify where AI may be used in this app or service.',
        safety: 'Review controls for personalization, history, location, microphone, and photo access.'
    },
    {
        number: 11, module: 1, week: 4, title: 'The Benefits of AI',
        objectives: ['Match AI benefits to personal needs.', 'Recognize realistic, small efficiency gains.'],
        points: ['AI can support writing, organization, idea generation, and learning.', 'Small improvements can reduce friction and mental load.'],
        activity: 'Rank five possible benefits by usefulness and explain your top choice.',
        prompt: 'Help me with one everyday task by saving time or organizing information.',
        safety: 'Review and personalize the result before using or sharing it.'
    },
    {
        number: 12, module: 1, week: 4, title: 'Building Your First AI Habit',
        objectives: ['Select one repeatable task.', 'Create a simple review routine.'],
        points: ['Pick one task, use one prompt, review, refine, and repeat.', 'Consistency matters more than complexity.'],
        activity: 'Create a one-week AI practice plan for one familiar task.',
        prompt: 'Help me use AI for this small task and tell me what to double-check.',
        safety: 'Keep the first habit low-risk, limited, and easy to review.'
    },
    {
        number: 13, module: 2, week: 5, title: 'Start Practical AI With Everyday Tasks',
        objectives: ['Select familiar, low-risk applications.', 'Judge whether an output will be easy to review.'],
        points: ['Strong first tasks are familiar, limited, useful, and low-risk.', 'Avoid complex interpretation when beginning.'],
        activity: 'Rate five possible tasks for familiarity, risk, usefulness, and reviewability.',
        prompt: 'Help me use AI for this everyday task: [insert task].',
        safety: 'Choose a task whose result you can personally recognize as useful or flawed.'
    },
    {
        number: 14, module: 2, week: 5, title: 'Better Prompts for Everyday Tasks',
        objectives: ['Apply task, context, format, and limits.', 'Improve vague requests.'],
        points: ['Specific instructions improve usefulness.', 'Audience, tone, length, and constraints shape the result.'],
        activity: 'Rewrite five vague prompts into practical versions with clear output requirements.',
        prompt: 'Take this rough request and turn it into a clearer prompt.',
        safety: 'A better prompt does not remove the need to verify facts.'
    },
    {
        number: 15, module: 2, week: 5, title: 'First Easy AI Uses to Try This Week',
        objectives: ['Complete one real task.', 'Document revisions and corrections.'],
        points: ['Practice builds confidence.', 'The reviewed final version matters more than the first output.'],
        activity: 'Record the task, prompt, first output, corrections, and final version.',
        prompt: 'Give me a clear answer, one useful example, and anything to double-check.',
        safety: 'Remove private information before using a real-life example.'
    },
    {
        number: 16, module: 2, week: 6, title: 'Safe AI Habits for Everyday Use',
        objectives: ['Sanitize prompts.', 'Use placeholders and review before sending.'],
        points: ['Privacy, clarity, review, and verification are core habits.', 'Use AI as a helper rather than a decision-maker.'],
        activity: 'Rewrite a sample prompt containing names, addresses, and client information.',
        prompt: 'Review this draft and identify anything private, unclear, or risky.',
        safety: 'Confidential work and client data require approved tools and organizational policies.'
    },
    {
        number: 17, module: 2, week: 6, title: 'Check Before You Trust the Answer',
        objectives: ['Identify claims that require verification.', 'Use a simple verification workflow.'],
        points: ['Check facts, dates, prices, policies, quotes, names, and high-stakes advice.', 'Official and primary sources are generally strongest.'],
        activity: 'Review a response containing a correct claim, an outdated claim, and a fabricated citation.',
        prompt: 'Review this answer and list the claims I should verify.',
        safety: 'Open and read a source before relying on or citing it.'
    },
    {
        number: 18, module: 2, week: 6, title: 'When to Use AI and When to Slow Down',
        objectives: ['Classify scenarios by risk.', 'Explain when professional guidance is needed.'],
        points: ['Drafting and organizing are usually low-risk.', 'Health, rights, money, safety, and eligibility require caution.'],
        activity: 'Classify scenarios as use normally, verify, seek authority, or do not share.',
        prompt: 'Tell me whether this task is a good fit for AI and what to verify.',
        safety: 'A polished response is not a substitute for qualified professional advice.'
    },
    {
        number: 19, module: 2, week: 7, title: 'Save Time With AI',
        objectives: ['Identify repetitive tasks.', 'Estimate realistic time savings.'],
        points: ['The goal is reduced friction, not maximum automation.', 'Small time savings can add up across a week.'],
        activity: 'Complete a time audit and identify one ten-minute opportunity.',
        prompt: 'Help me save time on this task: [insert task].',
        safety: 'Do not automate accountability, approval, or decisions you must understand.'
    },
    {
        number: 20, module: 2, week: 7, title: 'Get Organized With AI',
        objectives: ['Turn rough notes into structured plans.', 'Break large projects into next steps.'],
        points: ['AI can categorize, prioritize, and sequence information.', 'Missing details should be labeled rather than invented.'],
        activity: 'Transform mixed notes into categories, priorities, missing information, and next steps.',
        prompt: 'Organize these notes into a checklist and identify missing information.',
        safety: 'Confirm dates, owners, priorities, and dependencies yourself.'
    },
    {
        number: 21, module: 2, week: 7, title: 'Learn Faster With AI',
        objectives: ['Ask for plain-language explanations and examples.', 'Generate review questions.'],
        points: ['AI can explain, compare, quiz, and summarize.', 'Active practice is stronger than simply reading an answer.'],
        activity: 'Use the sequence: explain, example, compare, quiz, verify.',
        prompt: 'Explain [topic] like I am a beginner and tell me what to verify.',
        safety: 'Verify serious technical or consequential information through trusted sources.'
    },
    {
        number: 22, module: 2, week: 8, title: 'Build Your First AI Habit',
        objectives: ['Select one recurring task.', 'Create a trigger, prompt, review, and storage plan.'],
        points: ['A habit needs a clear cue and repeatable output.', 'Save only prompts that consistently work.'],
        activity: 'Complete a habit template covering when, why, how, review, and storage.',
        prompt: 'Help me use AI for this recurring task and create a review checklist.',
        safety: 'Stop or revise the habit if it creates more work or confusion.'
    },
    {
        number: 23, module: 2, week: 8, title: 'Make AI Part of Your Week',
        objectives: ['Design a restrained weekly routine.', 'Select two or three meaningful uses.'],
        points: ['AI can help plan, write, organize, learn, and reflect.', 'AI should support your week rather than run it.'],
        activity: 'Create a schedule with no more than three AI-supported activities.',
        prompt: 'Build a practical weekly AI routine using three tasks I already do.',
        safety: 'Keep tasks low-risk, reviewable, and aligned with real needs.'
    },
    {
        number: 24, module: 2, week: 8, title: 'Keep Your AI Habit Going',
        objectives: ['Reuse and refine prompts.', 'Maintain judgment and privacy.'],
        points: ['Save good prompts, ask follow-ups, review, and keep tasks focused.', 'Simple routines are easier to evaluate than random use.'],
        activity: 'Create a Personal AI Workflow Card for one recurring task.',
        prompt: 'Create a reusable prompt and three follow-up questions for this task.',
        safety: 'Do not become dependent on AI for decisions you should understand yourself.'
    },
    {
        number: 25, module: 3, week: 9, title: 'Start With One Small AI Win',
        objectives: ['Select a task with a clear success condition.', 'Avoid beginning with a large, undefined project.'],
        points: ['A strong first task is familiar, limited, low-risk, and reviewable.', 'Useful does not require perfection.'],
        activity: 'Turn three oversized goals into one-step AI tasks.',
        prompt: 'Help me complete one small part of this task: [insert task].',
        safety: 'Keep the scope small enough to review carefully.'
    },
    {
        number: 26, module: 3, week: 9, title: 'Easy Prompts to Get Started',
        objectives: ['Use reusable templates.', 'Replace variables for repeated tasks.'],
        points: ['Templates work for rewriting, summarizing, planning, and learning.', 'Strong templates state the output and review criteria.'],
        activity: 'Complete four fill-in prompt templates and save one for later.',
        prompt: 'Rewrite the following for [audience] in a [tone] tone.',
        safety: 'Remove sensitive details before saving or sharing prompt templates.'
    },
    {
        number: 27, module: 3, week: 9, title: 'Test, Review, and Improve Your First Prompt',
        objectives: ['Evaluate a first output.', 'Refine it through a follow-up request.'],
        points: ['Ask, review, identify gaps, revise, and save what works.', 'The first output is a draft, not a final answer.'],
        activity: 'Produce a before-and-after prompt comparison and note what improved.',
        prompt: 'Revise this answer by adding [missing detail] and using [format].',
        safety: 'Do not save a reusable prompt until it has been tested.'
    },
    {
        number: 28, module: 3, week: 10, title: 'Avoid Common Beginner AI Mistakes',
        objectives: ['Recognize five common mistakes.', 'Apply a quick fix to each.'],
        points: ['Common mistakes include vague questions, blind trust, oversharing, no follow-up, and treating AI as an expert.', 'Small corrections often create much better results.'],
        activity: 'Diagnose five short case studies and recommend one fix for each.',
        prompt: 'Review my prompt for anything vague, risky, or missing.',
        safety: 'Confidence of tone is not evidence of accuracy.'
    },
    {
        number: 29, module: 3, week: 10, title: 'Check Before You Trust the Answer',
        objectives: ['Distinguish stronger and weaker sources.', 'Create a claim-checking record.'],
        points: ['Official and primary sources are strongest for policies and deadlines.', 'AI-generated citations may be fabricated or mismatched.'],
        activity: 'Create a table for claim, source, date, confirmation, and notes.',
        prompt: 'List every factual claim in this answer that requires verification.',
        safety: 'Do not cite a source until you have opened it and confirmed the claim.'
    },
    {
        number: 30, module: 3, week: 10, title: 'When to Use AI and When to Slow Down',
        objectives: ['Apply the PAUSE framework.', 'Identify when expertise is required.'],
        points: ['PAUSE means Personal information, Accuracy, Uncertainty, Source, and Expertise.', 'Risk depends on the consequences of being wrong, not just the topic.'],
        activity: 'Apply PAUSE to six everyday scenarios and record the safest next step.',
        prompt: 'Apply the PAUSE test to this task and explain the risks.',
        safety: 'Pause before actions affecting health, rights, safety, eligibility, or money.'
    },
    {
        number: 31, module: 3, week: 11, title: 'Save Time With AI',
        objectives: ['Build a reusable time-saving prompt.', 'Separate variables from fixed instructions.'],
        points: ['Reusable workflows reduce setup time.', 'Review criteria should be built into the prompt.'],
        activity: 'Create a base prompt for a recurring email, summary, or planning task.',
        prompt: 'Turn these notes into decisions, tasks, deadlines, and unresolved questions.',
        safety: 'Tell the AI to label missing information instead of inventing it.'
    },
    {
        number: 32, module: 3, week: 11, title: 'Get Organized With AI',
        objectives: ['Prioritize and sequence tasks.', 'Recognize missing dates and dependencies.'],
        points: ['AI can group work by urgency and effort.', 'The learner must supply real deadlines and constraints.'],
        activity: 'Organize a project into quick wins, preparation tasks, and scheduled work.',
        prompt: 'Organize these tasks by urgency and effort without inventing deadlines.',
        safety: 'Confirm the proposed priority against real obligations.'
    },
    {
        number: 33, module: 3, week: 11, title: 'Learn Faster With AI',
        objectives: ['Use active learning.', 'Restate, test, correct, and verify.'],
        points: ['Learning improves when you actively retrieve and explain knowledge.', 'Ask AI to quiz you rather than simply provide answers.'],
        activity: 'Create a five-card study set and a short self-quiz.',
        prompt: 'Explain this topic, then quiz me without showing the answers first.',
        safety: 'Verify serious technical information through trusted sources.'
    },
    {
        number: 34, module: 3, week: 12, title: 'Build Your First AI Habit',
        objectives: ['Review whether a habit actually worked.', 'Decide to keep, change, or stop.'],
        points: ['Useful habits save time without reducing understanding.', 'A habit that creates new work should be redesigned.'],
        activity: 'Complete a six-question review of one AI-supported routine.',
        prompt: 'Help me evaluate this AI routine and suggest one improvement.',
        safety: 'Stop or redesign habits that weaken judgment or understanding.'
    },
    {
        number: 35, module: 3, week: 12, title: 'Make AI Part of Your Week',
        objectives: ['Build a restrained routine.', 'Limit use to meaningful tasks.'],
        points: ['A good routine solves a real problem and produces a reviewable output.', 'More AI use is not automatically better.'],
        activity: 'Choose no more than three weekly uses and define a review step for each.',
        prompt: 'Build a weekly AI routine around three tasks I already do.',
        safety: 'Keep yourself in control of the routine.'
    },
    {
        number: 36, module: 3, week: 12, title: 'Keep Your AI Habit Going',
        objectives: ['Save and categorize useful prompts.', 'Maintain independent judgment.'],
        points: ['Repeat, refine, reuse, review, and verify.', 'Consistency matters more than complexity.'],
        activity: 'Complete a Personal AI Playbook with prompts, review rules, and trusted sources.',
        prompt: 'Create a repeatable AI routine with a reusable prompt and review checklist.',
        safety: 'Never outsource your understanding of high-stakes decisions.'
    }
];

const STORAGE_KEY = 'cyberShieldLearningProgress';
const lessonList = document.getElementById('lessonList');
const lessonSearch = document.getElementById('lessonSearch');
const lessonEmpty = document.getElementById('lessonEmpty');
const progressText = document.getElementById('learningProgressText');
const progressBar = document.getElementById('learningProgressBar');
const accessMessage = document.getElementById('moduleAccessMessage');
const filterButtons = [...document.querySelectorAll('[data-module-filter]')];
const moduleCards = [...document.querySelectorAll('[data-module-card]')];
let selectedModule = 'all';

const readProgress = () => {
    try {
        const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
        return new Set(Array.isArray(saved) ? saved.map(Number).filter((number) => number >= 1 && number <= LESSONS.length) : []);
    } catch {
        return new Set();
    }
};

const completedLessons = readProgress();

const moduleLessons = (moduleNumber) => LESSONS.filter((lesson) => lesson.module === moduleNumber);
const moduleCompletedCount = (moduleNumber) => moduleLessons(moduleNumber)
    .filter((lesson) => completedLessons.has(lesson.number)).length;
const moduleIsComplete = (moduleNumber) => moduleCompletedCount(moduleNumber) === moduleLessons(moduleNumber).length;
const moduleIsUnlocked = (moduleNumber) => moduleNumber === 1 || [1, 2]
    .filter((prerequisite) => prerequisite < moduleNumber)
    .every(moduleIsComplete);
const highestUnlockedModule = () => [3, 2, 1].find(moduleIsUnlocked) || 1;

const saveProgress = () => {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify([...completedLessons].sort((a, b) => a - b)));
    } catch {
        // Progress remains available for this visit if storage is unavailable.
    }
};

const updateProgress = () => {
    const count = completedLessons.size;
    progressText.textContent = `${count} of ${LESSONS.length} complete | Module ${highestUnlockedModule()} unlocked`;
    progressBar.style.width = `${(count / LESSONS.length) * 100}%`;
};

const setActiveFilter = (moduleValue) => {
    selectedModule = String(moduleValue);
    filterButtons.forEach((button) => {
        const isActive = button.dataset.moduleFilter === selectedModule;
        button.classList.toggle('is-active', isActive);
        button.setAttribute('aria-pressed', String(isActive));
    });
};

const updateAccessMessage = () => {
    if (!moduleIsComplete(1)) {
        accessMessage.textContent = `Module 1: ${moduleCompletedCount(1)} of 12 lessons complete. Finish Module 1 to unlock Module 2.`;
    } else if (!moduleIsComplete(2)) {
        accessMessage.textContent = `Module 2 unlocked: ${moduleCompletedCount(2)} of 12 lessons complete. Finish Module 2 to unlock Module 3.`;
    } else if (!moduleIsComplete(3)) {
        accessMessage.textContent = `Module 3 unlocked: ${moduleCompletedCount(3)} of 12 lessons complete.`;
    } else {
        accessMessage.textContent = 'All three modules complete. Your full learning pathway is finished.';
    }
};

const updateModuleAccess = () => {
    moduleCards.forEach((card) => {
        const moduleNumber = Number(card.dataset.moduleCard);
        const unlocked = moduleIsUnlocked(moduleNumber);
        const access = card.querySelector('[data-module-access]');
        card.classList.toggle('is-locked', !unlocked);
        card.setAttribute('aria-disabled', String(!unlocked));
        if (access) {
            access.classList.toggle('is-unlocked', unlocked);
            access.lastChild.textContent = unlocked
                ? 'Available now'
                : `Complete Module ${moduleNumber - 1} to unlock`;
        }
    });

    filterButtons.forEach((button) => {
        const value = button.dataset.moduleFilter;
        if (value === 'all') return;
        const moduleNumber = Number(value);
        const unlocked = moduleIsUnlocked(moduleNumber);
        button.disabled = !unlocked;
        const iconUse = button.querySelector('use');
        if (iconUse) {
            const unlockedIcon = moduleNumber === 1 ? '#icon-brain' : moduleNumber === 2 ? '#icon-workflow' : '#icon-shield';
            iconUse.setAttribute('href', unlocked ? unlockedIcon : '#icon-lock');
        }
    });

    if (selectedModule !== 'all' && !moduleIsUnlocked(Number(selectedModule))) {
        setActiveFilter(highestUnlockedModule());
    }
    updateAccessMessage();
};

const makeList = (items) => {
    const list = document.createElement('ul');
    items.forEach((item) => {
        const entry = document.createElement('li');
        entry.textContent = item;
        list.append(entry);
    });
    return list;
};

const makeLessonBlock = (label, content, className = '') => {
    const block = document.createElement('div');
    block.className = `learning-lesson-block ${className}`.trim();
    const heading = document.createElement('h4');
    heading.textContent = label;
    block.append(heading);
    if (Array.isArray(content)) {
        block.append(makeList(content));
    } else {
        const paragraph = document.createElement('p');
        paragraph.textContent = content;
        block.append(paragraph);
    }
    return block;
};

const makeLesson = (lesson) => {
    const details = document.createElement('details');
    details.className = 'learning-lesson-card';
    details.dataset.module = String(lesson.module);
    details.id = `lesson-${lesson.number}`;

    const summary = document.createElement('summary');
    const marker = document.createElement('span');
    marker.className = 'learning-lesson-marker';
    marker.textContent = String(lesson.number).padStart(2, '0');

    const summaryCopy = document.createElement('span');
    summaryCopy.className = 'learning-lesson-summary-copy';
    const meta = document.createElement('span');
    meta.className = 'learning-lesson-meta';
    meta.textContent = `Module ${lesson.module} | Week ${lesson.week}`;
    const title = document.createElement('strong');
    title.textContent = lesson.title;
    summaryCopy.append(meta, title);

    const completion = document.createElement('label');
    completion.className = 'learning-complete-control';
    completion.title = `Mark lesson ${lesson.number} complete`;
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = completedLessons.has(lesson.number);
    checkbox.setAttribute('aria-label', `Mark lesson ${lesson.number} complete`);
    const checkLabel = document.createElement('span');
    checkLabel.textContent = 'Complete';
    completion.append(checkbox, checkLabel);
    completion.addEventListener('click', (event) => event.stopPropagation());
    completion.addEventListener('keydown', (event) => event.stopPropagation());
    checkbox.addEventListener('change', () => {
        const previousHighestModule = highestUnlockedModule();
        if (checkbox.checked) completedLessons.add(lesson.number);
        else completedLessons.delete(lesson.number);
        saveProgress();
        updateProgress();
        updateModuleAccess();
        if (highestUnlockedModule() !== previousHighestModule) renderLessons();
    });

    summary.append(marker, summaryCopy, completion);

    const body = document.createElement('div');
    body.className = 'learning-lesson-body';
    const topGrid = document.createElement('div');
    topGrid.className = 'learning-lesson-grid';
    topGrid.append(
        makeLessonBlock('Learning objectives', lesson.objectives),
        makeLessonBlock('Core teaching points', lesson.points)
    );
    body.append(
        topGrid,
        makeLessonBlock('Guided activity', lesson.activity),
        makeLessonBlock('Starter prompt', lesson.prompt, 'learning-prompt-block'),
        makeLessonBlock('Safety and review reminder', lesson.safety, 'learning-safety-block')
    );

    details.append(summary, body);
    return details;
};

const renderLessons = () => {
    const query = lessonSearch.value.trim().toLowerCase();
    const matches = LESSONS.filter((lesson) => {
        if (!moduleIsUnlocked(lesson.module)) return false;
        const moduleMatches = selectedModule === 'all' || String(lesson.module) === selectedModule;
        const searchText = [
            lesson.title,
            ...lesson.objectives,
            ...lesson.points,
            lesson.activity,
            lesson.prompt,
            lesson.safety
        ].join(' ').toLowerCase();
        return moduleMatches && (!query || searchText.includes(query));
    });

    lessonList.replaceChildren(...matches.map(makeLesson));
    lessonEmpty.hidden = matches.length > 0;
};

filterButtons.forEach((button) => {
    button.addEventListener('click', () => {
        const requestedModule = button.dataset.moduleFilter;
        if (requestedModule !== 'all' && !moduleIsUnlocked(Number(requestedModule))) return;
        setActiveFilter(requestedModule);
        renderLessons();
    });
});

document.querySelectorAll('[data-module-jump]').forEach((link) => {
    link.addEventListener('click', (event) => {
        const requestedModule = Number(link.dataset.moduleJump);
        if (!moduleIsUnlocked(requestedModule)) {
            event.preventDefault();
            accessMessage.textContent = `Module ${requestedModule} is locked. Complete all lessons in Module ${requestedModule - 1} first.`;
            link.classList.add('is-denied');
            window.setTimeout(() => link.classList.remove('is-denied'), 500);
            return;
        }
        setActiveFilter(requestedModule);
        lessonSearch.value = '';
        renderLessons();
    });
});

lessonSearch.addEventListener('input', renderLessons);
window.addEventListener('cybershield:lesson-complete', (event) => {
    const lessonNumber = Number(event.detail?.lessonNumber);
    if (!Number.isInteger(lessonNumber) || lessonNumber < 1 || lessonNumber > LESSONS.length) return;
    const previousHighestModule = highestUnlockedModule();
    completedLessons.add(lessonNumber);
    saveProgress();
    updateModuleAccess();
    updateProgress();
    if (highestUnlockedModule() !== previousHighestModule) renderLessons();
});
window.addEventListener('cybershield:progress-reset', () => {
    completedLessons.clear();
    saveProgress();
    selectedModule = 'all';
    lessonSearch.value = '';
    updateModuleAccess();
    updateProgress();
    renderLessons();
});
updateModuleAccess();
updateProgress();
renderLessons();
