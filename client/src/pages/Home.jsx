import React from 'react';
import Menubar from '../components/Menubar.jsx';
import Header from '../components/Header.jsx';

const Home = () => {
    return (
        <div>
            <div className="flex flex-col items-center justify-content-center min-vh-100">
                <Menubar />
                <Header />
            </div>
        </div>
    )
}

export default Home;