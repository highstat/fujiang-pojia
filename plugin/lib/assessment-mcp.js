import { assessmentTools, invokeAssessmentTool } from './assessment-tools.js';

export async function serveAssessmentMcp(service, input = process.stdin, output = process.stdout) {
  const versions = ['2024-11-05', '2025-03-26', '2025-06-18'];
  let initialized = false;
  let buffer = '';
  let chain = Promise.resolve();
  const send = value => new Promise((resolve, reject) => output.write(JSON.stringify(value) + '\n', error => error ? reject(error) : resolve()));
  const rpcError = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });
  async function dispatch(line) {
    let message;
    try { message = JSON.parse(line); } catch { await rpcError(null, -32700, 'Invalid JSON'); return; }
    if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string' || Array.isArray(message)
      || (message.id !== undefined && typeof message.id !== 'string' && typeof message.id !== 'number')) {
      await rpcError(null, -32600, 'Invalid JSON-RPC request'); return;
    }
    if (message.id === undefined) return;
    const reply = result => send({ jsonrpc: '2.0', id: message.id, result });
    if (message.method === 'initialize') {
      initialized = true;
      await reply({ protocolVersion: versions.includes(message.params?.protocolVersion) ? message.params.protocolVersion : versions.at(-1),
        capabilities: { tools: {} }, serverInfo: { name: 'fujiang-assessment', version: '1.0.0' } });
    } else if (message.method === 'ping') await reply({});
    else if (!initialized) await rpcError(message.id, -32000, 'Initialize the MCP session first.');
    else if (message.method === 'tools/list') await reply({ tools: assessmentTools(service).map(({ execute, ...tool }) => tool) });
    else if (message.method === 'tools/call') {
      if (!assessmentTools(service).some(tool => tool.name === message.params?.name)) { await rpcError(message.id, -32602, 'Unknown tool'); return; }
      try {
        const result = await invokeAssessmentTool(service, message.params.name, message.params.arguments ?? {});
        const content = JSON.stringify(result);
        if (Buffer.byteLength(content) > 2 * 1024 * 1024) throw new Error('Result exceeds 2 MiB; reduce pagination/graph limits.');
        await reply({ content: [{ type: 'text', text: content }], isError: false });
      } catch (error) { await reply({ content: [{ type: 'text', text: String(error.message).slice(0, 2000) }], isError: true }); }
    } else await rpcError(message.id, -32601, 'Method not found');
  }
  input.setEncoding('utf8');
  try {
    for await (const chunk of input) {
      buffer += chunk;
      if (Buffer.byteLength(buffer) > 1024 * 1024) throw new Error('MCP input exceeds 1 MiB.');
      let boundary;
      while ((boundary = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, boundary).trim();
        buffer = buffer.slice(boundary + 1);
        if (line) chain = chain.then(() => dispatch(line));
        await chain;
      }
    }
    if (buffer.trim()) await dispatch(buffer);
  } finally { await service.dispose(); }
}
