const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

function truncateLine(text, width) {
  if (!width || text.length <= width) return text;
  return text.slice(0, Math.max(0, width - 3)) + '...';
}

function treeLines(state) {
  return [
    FRAMES[state.frame % FRAMES.length],
    '├– Dorks:   ' + state.processed + ':' + state.total,
    '├– Success: ' + state.success,
    '├– Errors:  ' + state.errors,
    '├– Targets: ' + state.found,
    '└– ' + (state.file || state.category || 'discovery') + ': ' + (state.query || '...')
  ];
}

function createDiscoveryProgress(options = {}) {
  const stream = options.stream || process.stdout;
  const total = Math.max(0, Number(options.total) || 0);
  const interactive = Boolean(options.interactive);
  const state = {
    total,
    processed: 0,
    success: 0,
    errors: 0,
    found: 0,
    category: '',
    file: '',
    query: 'starting ...',
    frame: 0
  };
  const seenTargets = new Set();
  let lineCount = 0;
  let timer = null;

  const render = () => {
    const width = Math.max(40, (stream.columns || 100) - 1);
    const lines = treeLines(state).map((line) => truncateLine(line, width));
    if (interactive) {
      if (lineCount > 0) stream.write('\x1b[' + lineCount + 'A');
      for (const line of lines) stream.write('\r\x1b[2K' + line + '\n');
      lineCount = lines.length;
    } else {
      stream.write(lines.join('\n') + '\n');
    }
  };

  if (interactive) {
    try { stream.write('\x1b[?25l'); } catch (e) {}
    render();
    timer = setInterval(() => {
      state.frame = (state.frame + 1) % FRAMES.length;
      render();
    }, 100);
    if (timer.unref) timer.unref();
  }

  return {
    event(item) {
      state.processed++;
      if (item.error) state.errors++;
      else state.success++;
      if (Array.isArray(item.newTargets)) {
        for (const target of item.newTargets) seenTargets.add(target);
        state.found = seenTargets.size;
      } else {
        state.found += Number(item.added) || 0;
      }
      state.category = item.category || '';
      state.file = item.file || state.file;
      state.query = item.query || '';
      render();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
      if (interactive) {
        try { stream.write('\x1b[?25h'); } catch (e) {}
        render();
      }
    },
    stats() {
      return {
        total: state.total,
        processed: state.processed,
        success: state.success,
        errors: state.errors,
        found: state.found
      };
    }
  };
}

module.exports = { createDiscoveryProgress, FRAMES };
