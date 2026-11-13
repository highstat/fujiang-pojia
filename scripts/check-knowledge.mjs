import { validateKnowledgeCorpus, knowledgeFiles } from '../plugin/lib/knowledge-schema.js';
import { corpusRoot } from './normalize-knowledge.mjs';

const errors = validateKnowledgeCorpus(corpusRoot);
if (errors.length) {
  console.error(errors.join('\n'));
  process.exitCode = 1;
} else console.log('Knowledge schema valid: ' + knowledgeFiles(corpusRoot).length + ' entries.');
