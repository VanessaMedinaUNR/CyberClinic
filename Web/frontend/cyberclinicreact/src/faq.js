import { useState } from 'react';
import Toolbar from './Components/toolbar';
import './styles/faq.css';

const faqs = [
  {
    category: "About Us",
    items: [
      {
        question: "What is CyberClinic?",
        answer:
          "CyberClinic is a free cybersecurity tool built by students at the University of Nevada, Reno. We help small businesses, tribal agencies, and nonprofits find and understand security vulnerabilities in their systems without needing a technical background or a big budget.",
      },
      {
        question: "Who runs it?",
        answer:
          "We're Team 13, a group of four CS students at UNR working on this as our CS 426 Senior Project. The project is advised by Dr. Bill Doherty and Dr. Shamik Sengupta from UNR's Cybersecurity Center.",
      },
      {
        question: "Is this connected to a larger organization?",
        answer:
          "Yes. CyberClinic started as a student-led nonprofit at UNLV and is now expanding to UNR. The goal of the broader organization is to bring affordable cybersecurity help to communities that typically can't access it.",
      },
    ],
  },
  {
    category: "Using the Platform",
    items: [
      {
        question: "How does it work?",
        answer:
          "You create an account, enter a domain or IP address you want to scan, and we handle the rest. Our system runs the scan using Nmap and Nikto, then turns the raw results into a plain-English report that tells you what was found and what to do about it.",
      },
      {
        question: "What if my network isn't publicly accessible?",
        answer:
          "We have a standalone application you can download and run locally on your network. It scans internal subnets and sends the results back to the platform your data never leaves your environment.",
      },
      {
        question: "Do I need any technical knowledge to use this?",
        answer:
          "No. That's the whole point. The reports are written to be understood by anyone, not just IT professionals. If something needs fixing, we explain what it is and how to address it in plain language.",
      },
    ],
  },
  {
    category: "Reports",
    items: [
      {
        question: "What does a report actually look like?",
        answer:
          "Each report lists the vulnerabilities found, explains what they mean, and gives you clear next steps. There's no raw scanner output or technical jargon just a straightforward summary you can act on.",
      },
      {
        question: "Is AI involved in generating the reports?",
        answer:
          "Yes. We use Ollama, a locally-run AI model, to translate scanner output into readable summaries. Because it runs on our server and not through a third-party service, your scan data stays private.",
      },
    ],
  },
  {
    category: "Privacy & Security",
    items: [
      {
        question: "Is my data kept private?",
        answer:
          "Yes. Scan results and account information are kept confidential. We don't share your data with anyone, and our AI analysis runs locally so nothing gets sent to outside services.",
      },
      {
        question: "Is this free?",
        answer:
          "Completely free. This is a nonprofit student project there's no cost to create an account or run a scan.",
      },
    ],
  },
];

function FAQ() {
  const [openIndex, setOpenIndex] = useState(null);

  function toggle(key) {
    setOpenIndex(openIndex === key ? null : key);
  }

  return (
    <div id="faq-page">
      <Toolbar />
      <div id="bounding_box">

        <div className="gridItem mission-block">
          <h1>FAQ</h1>
          <p>Have questions about CyberClinic? Here are the ones we hear most often.</p>
        </div>

        {faqs.map((section, si) => (
          <div key={si}>
            <p className="faq-category">{section.category}</p>
            {section.items.map((item, ii) => {
              const key = `${si}-${ii}`;
              const isOpen = openIndex === key;
              return (
                <div key={key} className="gridItem faq-item">
                  <div className="faq-question-btn" onClick={() => toggle(key)}>
                    <h2 className="faq-question-text">{item.question}</h2>
                    <span className={`faq-chevron ${isOpen ? 'open' : ''}`}>▼</span>
                  </div>
                  {isOpen && (
                    <p className="faq-answer">{item.answer}</p>
                  )}
                </div>
              );
            })}
          </div>
        ))}

      </div>
    </div>
  );
}

export default FAQ;