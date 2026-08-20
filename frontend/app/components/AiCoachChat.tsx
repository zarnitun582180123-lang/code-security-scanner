// components/AiCoachChat.tsx
import React, { useState } from 'react';

interface AiCoachProps {
  vulnerability: {
    title: string;
    severity: string;
    filePath: string;
    lineNumber: number;
    snippet: string;
  };
}

export const AiCoachChat: React.FC<AiCoachProps> = ({ vulnerability }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: `မင်္ဂလာပါ။ **${vulnerability.title}** (${vulnerability.filePath}) အတွက် Secure Fix Code သို့မဟုတ် သိချင်တာများကို မေးမြန်းနိုင်ပါသည်။`
    }
  ]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    const userMsg = { role: 'user', content: input };
    const updatedMessages = [...messages, userMsg];
    setMessages(updatedMessages);
    setInput('');
    setLoading(true);

    try {
      // Backend သို့ Context + User Input ပေးပို့ခြင်း
     const res = await fetch('http://127.0.0.1:8000/api/ai-coach', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    vulnerability_type: issue.title,
    suggestion: input, // သင်ရိုက်လိုက်သော Hi သို့မဟုတ် မေးခွန်း
    vulnerable_code: issue.snippet
  }),
});

      const data = await response.json();
      if (data.success) {
        setMessages([...updatedMessages, { role: 'assistant', content: data.reply }]);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mt-2">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold flex items-center gap-1.5"
      >
        🤖 Ask AI Coach
      </button>

      {isOpen && (
        <div className="fixed bottom-4 right-4 w-[380px] h-[480px] bg-slate-900 border border-cyan-500/50 rounded-xl shadow-2xl flex flex-col z-50 overflow-hidden">
          {/* Header */}
          <div className="p-3 bg-slate-800 border-b border-slate-700 flex justify-between items-center">
            <span className="font-bold text-cyan-400 text-xs">ISVS Threat Advisor (Groq-Powered)</span>
            <button onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-white text-xs">✕</button>
          </div>

          {/* Chat Messages */}
          <div className="flex-1 p-3 overflow-y-auto space-y-2 text-xs">
            {messages.map((m, idx) => (
              <div
                key={idx}
                className={`p-2 rounded-lg max-w-[85%] ${
                  m.role === 'user'
                    ? 'bg-cyan-900/60 text-white ml-auto border border-cyan-500/30'
                    : 'bg-slate-800 text-gray-200 mr-auto border border-slate-700'
                }`}
              >
                <div className="whitespace-pre-wrap">{m.content}</div>
              </div>
            ))}
            {loading && <div className="text-gray-400 text-xs italic">AI Coach is thinking...</div>}
          </div>

          {/* Input Box */}
          <div className="p-2.5 border-t border-slate-800 flex gap-2 bg-slate-950">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ex: Express မှာ Prepared Statement ဘယ်လိုပြင်မလဲ?"
              className="flex-1 bg-slate-900 border border-slate-700 text-white text-xs rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            />
            <button
              onClick={handleSend}
              disabled={loading}
              className="bg-cyan-500 text-slate-950 font-bold px-3 py-1.5 rounded text-xs hover:bg-cyan-400 disabled:opacity-50"
            >
              Send
            </button>
          </div>
        </div>
      )}
    </div>
  );
};