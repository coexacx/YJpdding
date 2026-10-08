JSON.stringify((() => {
    const point = element => {
        const r = element.getBoundingClientRect();
        const x = r.x + r.width / 2, y = r.y + r.height / 2;
        const hit = document.elementFromPoint(x, y);
        return r.width > 5 && r.height > 5 && x > 0 && y > 0 && x < innerWidth && y < innerHeight &&
            (hit === element || element.contains(hit)) ? {x, y} : null;
    };
    // Only known privacy widgets' close/reject controls. Never click Accept All.
    for (const selector of [
        '#onetrust-consent-sdk #close-pc-btn-handler',
        '#onetrust-consent-sdk button.onetrust-close-btn-handler',
        '#onetrust-consent-sdk #onetrust-reject-all-handler'
    ]) {
        const button = document.querySelector(selector);
        const position = button && !button.disabled && point(button);
        if (position) return {url: location.href, dismiss: {...position, selector}, links: []};
    }
    const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 2000)
        .filter(a => !a.hasAttribute('download') && !a.hasAttribute('onclick') &&
            (!a.target || ['_self', '_blank'].includes(a.target)) &&
            !a.closest('form,[contenteditable="true"]') && a.getAttribute('role') !== 'button')
        .filter(a => {
            const r = a.getBoundingClientRect(), style = getComputedStyle(a);
            return r.width > 5 && r.height > 5 && style.visibility !== 'hidden' && style.opacity !== '0';
        })
        .map(a => ({href: a.href, text: (a.innerText || '').slice(0, 120)})).slice(0, 128);
    return {url: location.href, dismiss: null, links};
})())
