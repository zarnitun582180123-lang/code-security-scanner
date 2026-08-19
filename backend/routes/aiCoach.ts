import express from 'express';
import Groq from 'groq-sdk';

const router = express.Router();
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

router.post('/api/ai-coach', async (req, res) => {
  try {
    const { context, userPrompt, chatHistory } = req.body;

    // System Prompt ထဲသို့ Vulnerability Context အားလုံး ထည့်သွင်းခြင်း
    const systemInstruction = {
      role: 'system',
      content: `You are an expert Application Security Coach inside the ISVS (Identifying Security Vulnerabilities in Source Code) platform.

      CURRENT VULNERABILITY CONTEXT:
      - Title: ${context?.title || 'Security Vulnerability'}
      - Severity: ${context?.severity || 'UNKNOWN'}
      - File Path: ${context?.filePath || 'N/A'}
      - Line Number: ${context?.lineNumber || 'N/A'}
      - Vulnerable Snippet: ${context?.snippet || 'N/A'}

      INSTRUCTIONS:
      1. Provide direct, secure, and production-ready code fixes.
      2. Adapt answers to the tech stack mentioned by the user (e.g., Express, Nginx, React, PostgreSQL).
      3. Keep response concise, practical, and highly focused on remediation.`
    };

    // Chat History ပါဝင်ပါက ပေါင်းစပ်ပြီး Groq ထံ ပေးပို့ခြင်း
    const formattedMessages = [
      systemInstruction,
      ...(chatHistory || []),
      { role: 'user', content: userPrompt }
    ];

    const completion = await groq.chat.completions.create({
      messages: formattedMessages,
      model: 'llama-3.3-70b-versatile',
      temperature: 0.2,
      max_tokens: 1024,
    });

    const reply = completion.choices[0]?.message?.content || 'No response generated.';
    res.json({ success: true, reply });

  } catch (error: any) {
    console.error('Groq AI Coach Error:', error);
    res.status(500).json({ success: false, error: 'AI Coach response failed.' });
  }
});

export default router;