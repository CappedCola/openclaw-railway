---
name: exa-search
description: Web search and content retrieval using Exa.ai API. Use when searching the web, finding information online, or retrieving content from URLs.
homepage: https://exa.ai
metadata: {"clawdbot":{"emoji":"🌐","os":["darwin","linux","win32"],"requires":{"env":["EXA_API_KEY"]},"install":[{"id":"exa-js","kind":"npm","package":"exa-js","label":"Install Exa SDK"}]}}
---

# Exa Search - Web Search for AI

Exa.ai is a web search API built specifically for AI agents. It provides neural and keyword search with content extraction.

## When to use (trigger phrases)

- "search the web"
- "find information online"
- "look up"
- "web research"
- "get content from URL"
- "find similar pages"
- "research"

## Prerequisites

- Node.js >= 16
- EXA_API_KEY environment variable set

Get your API key at: https://dashboard.exa.ai/api-keys

## Install

`npm install exa-js`

## Quick Start

```typescript
import Exa from 'exa-js';

const exa = new Exa(process.env.EXA_API_KEY);

// Search the web
const result = await exa.searchAndContents(
  "latest AI developments",
  {
    type: "auto",
    numResults: 10,
    contents: {
      text: true
    }
  }
);
```

## Search Types

- `"auto"` (default): Automatically choose between neural and keyword
- `"fast"`: Quick keyword search
- `"deep"`: Comprehensive neural search
- `"deep-reasoning"`: Neural with reasoning (slower, higher quality)
- `"deep-max"`: Maximum depth search (slowest, highest quality)

## Common Patterns

### Basic Search with Content

```typescript
const results = await exa.searchAndContents(
  "quantum computing breakthroughs 2025",
  {
    type: "auto",
    numResults: 5,
    contents: {
      text: { maxCharacters: 1000 }
    }
  }
);

for (const result of results.results) {
  console.log(`${result.title}: ${result.url}`);
  console.log(result.text?.substring(0, 500));
}
```

### Find Similar Pages

```typescript
const similar = await exa.findSimilarAndContents(
  "https://example.com/article",
  {
    numResults: 5,
    contents: { text: true }
  }
);
```

### Get Answer to Question

```typescript
const answer = await exa.answer("What is the capital of France?");
console.log(answer);
```

## Content Options

Control what content is returned:

```typescript
contents: {
  text: true,                          // Full text extraction
  text: { maxCharacters: 1000 },       // Truncated text
  highlights: {                        // Key passages
    numSentences: 3,
    highlightsPerUrl: 2
  },
  summary: { query: "your query" }     // LLM-generated summary
}
```

## Webpage Retrieval

Get content from a specific URL:

```typescript
const page = await exa.getContents(
  "https://example.com",
  { text: true }
);
```

## Research Mode

For comprehensive research tasks:

```typescript
// Start a research job
const task = await exa.research.create({
  query: "Climate change impacts on agriculture",
  plan: true  // Get the research plan before execution
});

// Poll until complete
const result = await exa.research.pollUntilFinished(task.researchId);
```

## Rate Limits & Best Practices

- Free tier: 100 requests/month
- Pro tier: 10,000 requests/month
- Enterprise: Custom limits

Tips:
- Use `type: "fast"` for quick lookups
- Use `type: "deep"` for comprehensive research
- Cache results when possible
- Use `numResults` to limit response size

## Error Handling

```typescript
try {
  const results = await exa.searchAndContents(query);
} catch (error) {
  if (error.status === 429) {
    // Rate limit exceeded
  } else if (error.status === 401) {
    // Invalid API key
  }
}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `EXA_API_KEY` | Yes | Your Exa API key |

## Related

- Documentation: https://docs.exa.ai
- API Reference: https://docs.exa.ai/reference
- TypeScript SDK: https://github.com/exa-labs/exa-js
