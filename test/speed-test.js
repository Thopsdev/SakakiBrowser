#!/usr/bin/env node
/**
 * Speed Test
 *
 * FastBrowser の速度改善を測定
 */

const http = require('http');

const BASE_URL = 'http://localhost:18800';

async function request(path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method: body ? 'POST' : 'GET',
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      headers: body ? { 'Content-Type': 'application/json' } : {}
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function measureTime(name, fn) {
  const start = Date.now();
  const result = await fn();
  const time = Date.now() - start;
  console.log(`  ${name}: ${time}ms`);
  return { result, time };
}

async function main() {
  console.log('='.repeat(60));
  console.log('Speed Test - FastBrowser vs Traditional');
  console.log('='.repeat(60));

  // 1. FastBrowser 初期化
  console.log('\n[1] FastBrowser 初期化');
  await measureTime('init', () => request('/fast/init', {}));

  // 2. 速度比較: ページを開く
  console.log('\n[2] ページを開く (example.com)');

  // 従来方式
  const traditional = await measureTime('Traditional /navigate', () =>
    request('/navigate', { url: 'https://example.com', skipSecurityCheck: true })
  );

  // FastBrowser
  const fast = await measureTime('FastBrowser /fast/open', () =>
    request('/fast/open', { url: 'https://example.com' })
  );

  console.log(`\n  改善率: ${Math.round((1 - fast.time / traditional.time) * 100)}%`);

  // 3. 連続アクセス (プール効果)
  console.log('\n[3] 連続アクセス (5回)');

  const times = [];
  for (let i = 0; i < 5; i++) {
    const { time } = await measureTime(`  リクエスト ${i + 1}`, () =>
      request('/fast/open', { url: 'https://example.com' })
    );
    times.push(time);

    // ページを閉じる
    const result = await request('/fast/open', { url: 'https://example.com' });
    if (result.pageId) {
      await request('/fast/close', { pageId: result.pageId });
    }
  }

  console.log(`\n  平均: ${Math.round(times.reduce((a, b) => a + b) / times.length)}ms`);
  console.log(`  最小: ${Math.min(...times)}ms`);
  console.log(`  最大: ${Math.max(...times)}ms`);

  // 4. 統計
  console.log('\n[4] 統計');
  const stats = await request('/fast/stats');
  console.log(`  ブラウザプール: ${stats.pool?.browsers || 0} browsers`);
  console.log(`  利用可能ページ: ${stats.pool?.availablePages || 0}`);
  console.log(`  ページ再利用: ${stats.pool?.pagesReused || 0}`);
  console.log(`  ブロックされたリソース: ${stats.pool?.blockRate || 0}%`);
  console.log(`  平均ページロード: ${stats.pool?.avgPageLoadTime || 0}ms`);

  // 5. セマンティック検索テスト
  console.log('\n[5] セマンティック検索テスト');

  // ページを開く
  const pageResult = await request('/fast/open', { url: 'https://example.com' });
  if (pageResult.success) {
    // DOM取得
    const dom = await measureTime('DOM取得', () =>
      request('/fast/dom', { pageId: pageResult.pageId })
    );

    // テキスト取得
    const text = await measureTime('テキスト取得 (h1)', () =>
      request('/fast/get-text', { pageId: pageResult.pageId, target: 'h1' })
    );

    if (text.result.success) {
      console.log(`  取得したテキスト: "${text.result.text}"`);
    }

    // クリーンアップ
    await request('/fast/close', { pageId: pageResult.pageId });
  }

  // 6. 要素検索統計
  console.log('\n[6] 要素検索統計');
  const finderStats = stats.finder || {};
  console.log(`  検索成功率: ${finderStats.successRate || 0}%`);
  console.log(`  戦略ヒット:`, finderStats.strategyHits || {});

  console.log('\n' + '='.repeat(60));
  console.log('テスト完了');
  console.log('='.repeat(60));
}

main().catch(console.error);
