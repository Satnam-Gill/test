'use client'
import React, { useState, useEffect } from "react";
import Image from 'next/image';     

const WeatherWidget_LatLon: React.FC = () => {
    const [city, setCity] = useState<string>("");
    const [weather, setWeather] = useState<{ icon: JSX.Element | null; temperature: string | null }>({ icon: null, temperature: null });

    useEffect(() => {
        if (city) {
            fetchWeather(city);
        }
    }, [city]);

    const fetchWeather = async (cityName: string) => {
        try {
            const weatherReq = await fetch(`https://api.weatherapi.com/v1/forecast.json?key=ee94006c9bb74ce892f181126211305&q=${cityName}&days=1&aqi=no&alerts=no`);
            const weatherData = await weatherReq.json();
            setWeather({
                icon: (
                    <Image
                        src={"https:" + weatherData.current.condition.icon}
                        alt={`It is ${weatherData.current.temp_c} in ${cityName}`}
                        width={80}
                        height={80}
                    />
                ),
                temperature: weatherData.current.temp_c + "º C",
            });
        } catch (error) {
            console.error("WeatherError", error);
        }
    };

    return (
        <div className="min-w-min bg-white border border-blue-200 rounded-lg p-4 m-5">
            <div className="row">
                <h1 className="text-lg font-bold text-gray-600">Weather for {city}</h1>
            </div>
            <div className="row">
                <input
                    type="text"
                    placeholder="Enter city name"
                    className="border border-gray-400 p-2 text-black rounded"
                    onChange={(e) => setCity(e.target.value)}
                />
            </div>
            <div className="row mt-4">
                <div className="p-2">{weather.icon}</div>
                <div className="text-3xl font-bold text-gray-600 mt-6">{weather.temperature}</div>
            </div>
        </div>
    );
};

export default WeatherWidget_LatLon;