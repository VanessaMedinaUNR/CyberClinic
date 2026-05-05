////used https://thomson.hashnode.dev/building-a-dark-theme-toggle-in-react-a-simple-guide-for-frontend-developers
//https://blog.logrocket.com/dark-mode-react-in-depth-guide/
import { useState,useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

import '../styles/darkmode.css';

function DarkModeToggle() {
    const [isDark, setIsDark] = useState(localStorage.getItem('theme') === 'dark');
  
    useEffect(() => {
      if (isDark) {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
      } else {
        document.documentElement.setAttribute('data-theme', 'light');
        localStorage.setItem('theme', 'light');
      }
    }, [isDark]);
  
    return (
      <button 
        className="dark-mode-btn"
        aria-pressed={isDark} 
        onClick={() => setIsDark(!isDark)}
      >
        {isDark ? '☀️ Light' : '🌙 Dark'}
      </button>
    );
}
  
export default DarkModeToggle;