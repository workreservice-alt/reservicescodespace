import React, { createContext, useContext, useEffect, useState } from 'react';
import io from 'socket.io-client';
import { useUser } from './UserContext';

const SocketContext = createContext();

export const useSocket = () => useContext(SocketContext);

export const SocketProvider = ({ children }) => {
    const { user, isAuthenticated } = useUser();
    const [socket, setSocket] = useState(null);

    useEffect(() => {
        if (isAuthenticated && user) {
            // Initialize socket connection
            // Handle both absolute (https://...) and relative (/api/v1) URLs
            const vApiUrl = import.meta.env.VITE_API_URL || '';
            let socketUrl;

            try {
                if (vApiUrl.startsWith('http')) {
                    socketUrl = new URL(vApiUrl.replace('/api/v1', '')).origin;
                } else {
                    // It's a relative path or empty, use current origin
                    socketUrl = window.location.origin;
                }
            } catch (err) {
                console.error('Socket URL parsing failed, falling back to origin:', err);
                socketUrl = window.location.origin;
            }

            const newSocket = io(socketUrl, {
                withCredentials: true,
                autoConnect: true,
                reconnection: true,
                reconnectionAttempts: 5,
                reconnectionDelay: 1000,
            });

            setSocket(newSocket);

            newSocket.on('connect', () => {
            });

            newSocket.on('connect_error', (err) => {
                console.error('Socket connection error:', err);
            });

            return () => {
                newSocket.disconnect();
            };
        } else {
            if (socket) {
                socket.disconnect();
                setSocket(null);
            }
        }
    }, [isAuthenticated, user?.id]); // Re-connect only if user changes or auth state changes

    return (
        <SocketContext.Provider value={{ socket }}>
            {children}
        </SocketContext.Provider>
    );
};
