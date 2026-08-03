(() => {
    const gateway = document.getElementById('learningGateway');
    const continueButtons = [
        document.getElementById('learningGatewayContinue'),
        document.getElementById('learningGatewayMobileContinue')
    ].filter(Boolean);
    const returnLinks = [
        document.getElementById('learningGatewayReturn'),
        document.getElementById('learningGatewayMobileReturn')
    ].filter(Boolean);

    if (!gateway || !continueButtons.length) return;

    const mainPageFallback = 'https://tylerbailey216.github.io/gtbaileyitsolutionsmain/';
    let returnDestination = mainPageFallback;

    try {
        if (document.referrer) {
            const referrer = new URL(document.referrer);
            if (referrer.origin !== window.location.origin) returnDestination = referrer.href;
        }
    } catch (_) {
        returnDestination = mainPageFallback;
    }

    returnLinks.forEach((link) => {
        link.href = returnDestination;
    });

    document.body.classList.add('learning-gateway-open');

    const enterLearningHub = () => {
        if (gateway.classList.contains('is-closing')) return;
        gateway.classList.add('is-closing');
        document.body.classList.remove('learning-gateway-open');

        window.setTimeout(() => {
            gateway.hidden = true;
            const learningHub = document.getElementById('top');
            if (learningHub) {
                learningHub.setAttribute('tabindex', '-1');
                learningHub.focus({ preventScroll: true });
            }
        }, 420);
    };

    continueButtons.forEach((button) => button.addEventListener('click', enterLearningHub));
    window.requestAnimationFrame(() => continueButtons[0].focus({ preventScroll: true }));
})();
