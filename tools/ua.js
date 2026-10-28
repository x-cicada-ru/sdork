const { loadJson } = require('./loader');

const LANGUAGES = [
  'en-US,en;q=0.9',
  'en-GB,en;q=0.8',
  'ru-RU,ru;q=0.9,en;q=0.8',
  'de-DE,de;q=0.9,en;q=0.8',
  'fr-FR,fr;q=0.9,en;q=0.7',
  'es-ES,es;q=0.9,en;q=0.8',
  'pl-PL,pl;q=0.9,en;q=0.8',
  'nl-NL,nl;q=0.9,en;q=0.8'
];

let pool = null;

function agents() {
  if (!pool) {
    try {
      const loaded = loadJson('user-agents/ua.json').user_agents;
      pool = Array.isArray(loaded) && loaded.length
        ? loaded
        : ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36'];
    } catch (err) {
      pool = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36'];
    }
  }
  return pool;
}

function randomAgent() {
  const list = agents();
  return list[Math.floor(Math.random() * list.length)];
}

function randomLanguage() {
  return LANGUAGES[Math.floor(Math.random() * LANGUAGES.length)];
}

module.exports = { agents, randomAgent, randomLanguage };
