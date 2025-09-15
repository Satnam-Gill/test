'use client'
import { useState } from "react";

type Mode = 'event' | 'construction';

const PortaPottyCalculator = () => {
  const [mode, setMode] = useState<Mode>('event');
  const [guests, setGuests] = useState<number>(0);
  const [duration, setDuration] = useState<number>(0);
  const [units, setUnits] = useState<number>(0);
  const [hasCalculated, setHasCalculated] = useState<boolean>(false);

  const isInputValid = guests > 0 && duration > 0;

  const handleCalculate = () => {
    if (isInputValid) {
      const result = Math.ceil((guests * duration) / 50);
      setUnits(result);
      setHasCalculated(true);
    }
  };

  return (
    <div className="max-w-6xl mx-auto py-12 px-6 md:px-12 grid grid-cols-1 md:grid-cols-2 gap-12 items-center">
      
      {/* LEFT: Heading + Subtext */}
      <div className="text-left">
        <h1 className="text-4xl font-bold text-gray-800 leading-snug mb-4">
          How Many Porta Potties Do You Need?
        </h1>
        <p className="text-lg text-gray-600">
          Use our quick calculator to estimate how many units you’ll need based on your event size and duration. Ideal for weddings, outdoor parties, and large gatherings.
        </p>
      </div>

      {/* RIGHT: Calculator */}
      <div className="bg-white p-8 shadow-2xl rounded-xl border border-gray-100 transform md:scale-110 transition-transform duration-300">
        <div className="flex justify-center gap-4 mb-6">
          <button
            onClick={() => setMode('event')}
            className={`px-5 py-2 rounded-full text-xl font-medium transition-all duration-300 ${
              mode === 'event'
                ? 'bg-minor text-white shadow-md'
                : 'text-white hover:bg-main'
            }`}
          >
            Porta Potty Calculator
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          <div>
            <label className="text-lg font-medium text-gray-700 block mb-1">
              How many guests?
              <span className="text-xs block text-gray-400">Enter number of attendees</span>
            </label>
            <input
              type="number"
              min="0"
              value={guests}
              onChange={(e) => setGuests(Number(e.target.value))}
              placeholder="e.g. 150"
              className="w-full px-4 py-2 border rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="text-lg font-medium text-gray-700 block mb-1">
              Event duration (hours)?
              <span className="text-xs block text-gray-400">Total hours of the event</span>
            </label>
            <input
              type="number"
              min="0"
              value={duration}
              onChange={(e) => setDuration(Number(e.target.value))}
              placeholder="e.g. 4"
              className="w-full px-4 py-2 border rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>

        {/* Calculate Button */}
        <div className="text-center mt-6">
          <button
            onClick={handleCalculate}
            disabled={!isInputValid}
            className={`px-6 py-2 rounded-full shadow transition-all duration-300 font-medium ${
              isInputValid
                ? 'bg-minor text-white hover:bg-gray-900 cursor-pointer'
                : 'bg-gray-300 text-gray-500 cursor-not-allowed'
            }`}
          >
            Calculate
          </button>
        </div>

        {/* Show Result Only After Clicking */}
        {hasCalculated && (
          <div className="text-center mt-8 transition-opacity duration-300 ease-in-out">
            <p className="text-lg text-black-500">Estimated Units Required:</p>
            <p className="text-5xl font-bold text-minor">{units}</p>
            <p className="text-xs text-gray-400 mt-1">For {guests || 0} guests & {duration || 0} hour(s)</p>

            {/* Contact CTA */}
            <div className="mt-6">
              <a
                href="/contact"
                className="inline-block px-6 py-2 bg-minor text-white font-medium rounded-full hover:bg-main transition"
              >
                Contact Us
              </a>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PortaPottyCalculator;
