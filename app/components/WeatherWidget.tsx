'use client'
import Image from 'next/image';
import { useEffect, useState } from 'react';

interface Weather {
  description: string;
  icon: string;
}

interface WeatherData {
  main: {
    temp: number;
  };
  name: string;
  weather: Weather[];
}

const WeatherWidget = () => {
  const [weatherData, setWeatherData] = useState<WeatherData | null>(null);

  useEffect(() => {
    navigator.geolocation.getCurrentPosition(async (position) => {
      const { latitude, longitude } = position.coords;
      const url = `https://open-weather13.p.rapidapi.com/city/latlon/${latitude}/${longitude}`;
      const options = {
        method: 'GET',
        headers: {
          'X-R Generic API Key': 'f398f4192amsh4101bab2f9e6d59p108165jsna3ac65f2adfb',
          'X-RapidAPI-Host': 'open-weather13.p.rapidapi.com'
        }
      };

      try {
        const response = await fetch(url, options);
        const result: WeatherData = await response.json(); // Parse JSON response
        if (result && result.main && result.weather) {
          setWeatherData(result);
        } else {
          setWeatherData(null);
        }
      } catch (error) {
        console.error(error);
      }
    });
  }, []);

  // Function to get weather icon URL
  const getWeatherIconUrl = () => {
    if (weatherData && weatherData.weather && weatherData.weather.length > 0) {
      const icon = weatherData.weather[0].icon;
      return `http://openweathermap.org/img/wn/${icon}.png`;
    }
    return '/sanitizer.png';
  };

  return (
    <div>
      <h1>Weather Widget</h1>
      {weatherData && weatherData.main && weatherData.weather && weatherData.weather.length > 0 ? (
        <>
          <p>Temperature: {(weatherData.main.temp - 273.15).toFixed(2)}°C</p>
          <p>City: {weatherData.name}</p>
          <p>Description: {weatherData.weather[0].description}</p>
          <Image src={getWeatherIconUrl()} alt="Weather icon" height={100} width={100}/>
        </>
      ) : (
        <p>Loading...</p>
      )}
    </div>
  );
};

export default WeatherWidget;
