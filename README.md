# Capstone
Agent-Based Risk Analysis and Assessment on Windows-Based Machines Using the ISO 27001 Standard <br/>

This project implements a fully local, agent-based AI system that performs automated risk analysis and assessment on Windows-based machines using Generative AI, structured tools, and Retrieval-Augmented Generation (RAG). The system provides a web-based GUI, local LLM inference, and persistent audit-ready results without relying on external cloud services.

---

## Key Features

- Fully local LLM inference (no external APIs required)
- Agent-based workflow using structured tools and stateful orchestration
- Automated collection and analysis of system security information
- ISO 27001–aligned risk assessment and compliance mapping
- Retrieval-Augmented Generation (RAG) using local vector database
- Web-based GUI with real-time agent execution timeline
- Persistent storage of reports, artifacts, and audit logs
- Modular architecture for extensibility and integration

---


 React Web GUI
=======
## Architecture Overview

```
            React Web GUI
                 │
                 ▼
   FastAPI Backend (API + Event Streaming)
                 │
                 ▼
        Agent Runtime (LangGraph)
        ├── Tool Execution Layer
        ├── RAG (Chroma Vector Database)
        ├── Local LLM Inference (Ollama / llama.cpp)
        └── Report Generation
                 │
                 ▼
     Local Storage (Artifacts, Logs, Reports)
=======
```


---

## Technology Stack

- Frontend: React + Vite
- Backend: FastAPI (Python)
- ChromaDB for vector storage and RAG memory
- LangGraph for orchestration and step-based agent execution
- Ollama for local chat + embeddings
- JSON/CSV as the authoritative workflow store for now
---

## Project Structure
app/ <br/>
├── src/ # React web interface <br/>
├── api/ # FastAPI backend <br/>
├── agent/ # Agent workflows, tools, schemas <br/>
├── data/ # Vector database and artifacts <br/>
└── storage/ # Reports, logs, and run metadata

Capstone-main/ <br/>
│ <br/>
├── app/ <br/>
│   ├── main.py <br/>
│   ├── agent/  # Agent workflows, tools, schemas <br/>
│   ├── api/     # FastAPI backend <br/>
│   ├── chroma_db/  <br/>
│   ├── llm/    (LLM integration modules) <br/>
│   ├── rag/ <br/>
│   ├── reports/    (report generation) <br/>
│   ├── src/                     ← Frontend  <br/>
│   │   ├── api/ <br/>
│   │   ├── components/ <br/>
│   │   └── pages/    # React web interface <br/>
│   └── storage/    (persistent runtime storage) <br/>
├── data/ <br/>
│   ├── work/     # Working files <br/>
│   ├── /docs     # Reference files  <br/>
│   └── raw/      # Json files <br/>
└── (project root)