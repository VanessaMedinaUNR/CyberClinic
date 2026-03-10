import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Home from './Home';

test('renders home page content', () => {
    render(<MemoryRouter><Home /></MemoryRouter>);
    expect(screen.getByText('CyberClinic')).toBeInTheDocument();
    expect(screen.getByText('Who Are We?')).toBeInTheDocument();
    expect(screen.getByText('Our Mission')).toBeInTheDocument();
});

test('login button is on the page', () => {
    render(<MemoryRouter><Home /></MemoryRouter>);
    const loginBtn = screen.getByText('Login / Create');
    expect(loginBtn).toBeInTheDocument();
});

test('FAQ button is on the page', () => {
    render(<MemoryRouter><Home /></MemoryRouter>);
    const faqBtn = screen.getByText('FAQ');
    expect(faqBtn).toBeInTheDocument();
});

test('Who Are We section has correct description', () => {
    render(<MemoryRouter><Home /></MemoryRouter>);
    const text = screen.getByText(/University of Nevada, Reno/i);
    expect(text).toBeInTheDocument();
});