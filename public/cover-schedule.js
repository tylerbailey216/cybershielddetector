(function () {
    const coverSchedule = [
        {
            id: 'august-2026',
            activateOn: '2026-08-01',
            month: 'August 2026',
            title: 'Introduction to Artificial Intelligence for Beginners',
            src: './monthly-covers/2026-08.png',
            alt: 'August 2026 Digital Literacy and Awareness cover introducing artificial intelligence for beginners'
        },
        {
            id: 'september-2026',
            activateOn: '2026-08-31',
            month: 'September 2026',
            title: 'Practical AI for Everyday Life',
            src: './monthly-covers/2026-09.png',
            alt: 'September 2026 Digital Literacy and Awareness cover about practical AI for everyday life'
        },
        {
            id: 'october-2026',
            activateOn: '2026-09-30',
            month: 'October 2026',
            title: 'Beginner AI for Everyday Life',
            src: './monthly-covers/2026-10.png',
            alt: 'October 2026 Digital Literacy and Awareness cover about beginner AI for everyday life'
        },
        {
            id: 'november-2026',
            activateOn: '2026-10-31',
            month: 'November 2026',
            title: 'November Learning Issue',
            src: './monthly-covers/2026-11.png',
            alt: 'November 2026 Digital Literacy and Awareness learning issue cover'
        }
    ];

    const localDateKey = (date = new Date()) => {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    };

    const eligibleCovers = (dateKey) => coverSchedule
        .filter((cover) => cover.activateOn <= dateKey)
        .sort((a, b) => b.activateOn.localeCompare(a.activateOn));

    const formatActivationDate = (dateKey) => new Intl.DateTimeFormat('en-US', {
        month: 'long',
        day: 'numeric',
        year: 'numeric'
    }).format(new Date(`${dateKey}T12:00:00`));

    const imageIsAvailable = (src) => new Promise((resolve) => {
        const probe = new Image();
        probe.onload = () => resolve(true);
        probe.onerror = () => resolve(false);
        probe.src = src;
    });

    const updateScheduleNote = (activeCover, dateKey, note) => {
        const nextCover = coverSchedule.find((cover) => cover.activateOn > dateKey);
        const scheduledButMissing = coverSchedule
            .filter((cover) => cover.activateOn <= dateKey)
            .find((cover) => cover.activateOn > activeCover.activateOn);

        if (scheduledButMissing) {
            note.textContent = `${scheduledButMissing.month} is scheduled. Add ${scheduledButMissing.src.split('/').pop()} to publish it automatically.`;
        } else if (nextCover) {
            note.textContent = `Next scheduled cover: ${nextCover.month} on ${formatActivationDate(nextCover.activateOn)}.`;
        } else {
            note.textContent = 'Future monthly cover slot ready for the next scheduled issue.';
        }
    };

    const selectScheduledCover = async (dateKey = localDateKey()) => {
        const image = document.getElementById('monthlyCoverImage');
        const label = document.getElementById('monthlyCoverLabel');
        const title = document.getElementById('monthlyCoverTitle');
        const note = document.getElementById('monthlyCoverSchedule');
        if (!image || !label || !title || !note) return null;

        const candidates = eligibleCovers(dateKey);
        for (const cover of candidates) {
            if (!(await imageIsAvailable(cover.src))) continue;
            image.src = cover.src;
            image.alt = cover.alt;
            label.textContent = `Monthly cover | ${cover.month}`;
            title.textContent = cover.title;
            updateScheduleNote(cover, dateKey, note);
            return cover;
        }

        note.textContent = 'The current cover could not be loaded. Add an available cover to the monthly-covers folder.';
        return null;
    };

    window.COVER_SCHEDULE = coverSchedule;
    window.selectScheduledCover = selectScheduledCover;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => selectScheduledCover(), { once: true });
    } else {
        selectScheduledCover();
    }
}());
