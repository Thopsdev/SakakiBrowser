async function attachRequestInterception(page, handler, backend) {
  if (!page || typeof handler !== 'function') return;

  if (backend === 'playwright') {
    await page.route('**/*', async (route) => {
      const req = route.request();
      const wrapped = {
        url: () => req.url(),
        resourceType: () => req.resourceType(),
        abort: () => route.abort(),
        continue: () => route.continue()
      };
      try {
        await handler(wrapped);
      } catch {
        await route.continue();
      }
    });
    return;
  }

  await page.setRequestInterception(true);
  if (typeof page.removeAllListeners === 'function') {
    page.removeAllListeners('request');
  }
  page.on('request', handler);
}

module.exports = { attachRequestInterception };

