"use client";
import Image from "next/image";
import React, { useState, useCallback } from "react";
import { FaTimes, FaChevronLeft, FaChevronRight } from "react-icons/fa";

// Lightbox Modal Component
const Lightbox = ({ 
  images, 
  currentIndex, 
  isOpen, 
  onClose, 
  onNext, 
  onPrev 
}: {
  images: string[];
  currentIndex: number;
  isOpen: boolean;
  onClose: () => void;
  onNext: () => void;
  onPrev: () => void;
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[999] flex items-center justify-center bg-black/95">
      {/* Close button */}
      <button
        onClick={onClose}
        className="absolute right-4 top-4 z-10 rounded-full bg-black/70 p-3 text-white hover:bg-black/90 transition-all duration-200"
      >
        <FaTimes size={20} />
      </button>
      
      {/* Navigation buttons */}
      {images.length > 1 && (
        <>
          <button
            onClick={onPrev}
            className="absolute left-4 top-1/2 z-10 -translate-y-1/2 rounded-full bg-black/70 p-3 text-white hover:bg-black/90 transition-all duration-200"
          >
            <FaChevronLeft size={20} />
          </button>
          <button
            onClick={onNext}
            className="absolute right-4 top-1/2 z-10 -translate-y-1/2 rounded-full bg-black/70 p-3 text-white hover:bg-black/90 transition-all duration-200"
          >
            <FaChevronRight size={20} />
          </button>
        </>
      )}
      
      {/* Image */}
      <div className="relative h-[90vh] w-full p-8">
        <Image
          src={images[currentIndex]}
          alt={`Gallery image ${currentIndex + 1}`}
          fill
          className="object-contain"
          priority
        />
      </div>
      
      {/* Image counter */}
      {images.length > 1 && (
        <div className="absolute bottom-6 left-1/2 -translate-x-1/2 rounded-full bg-black/70 px-4 py-2 text-white">
          {currentIndex + 1} / {images.length}
        </div>
      )}
    </div>
  );
};

interface GalleryGridProps {
  galleryData: any[];
}

const GalleryGrid: React.FC<GalleryGridProps> = ({ galleryData }) => {
  const [lightboxOpen, setLightboxOpen] = useState(false);
  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  const [allImages, setAllImages] = useState<string[]>([]);

  // Collect all images from gallery data
  const getAllImages = () => {
    const images: string[] = [];
    
    galleryData.forEach((gallery: any) => {
      gallery.images.forEach((item: any) => {
        if (gallery.id === "before-after") {
          images.push(item.beforeImage, item.afterImage);
        } else {
          images.push(item.image);
        }
      });
    });
    
    return images;
  };

  const openLightbox = (imageSrc: string) => {
    const images = getAllImages();
    const index = images.indexOf(imageSrc);
    setAllImages(images);
    setCurrentImageIndex(index);
    setLightboxOpen(true);
  };

  const closeLightbox = () => {
    setLightboxOpen(false);
  };

  const nextImage = useCallback(() => {
    setCurrentImageIndex((prev) => (prev + 1) % allImages.length);
  }, [allImages.length]);

  const prevImage = useCallback(() => {
    setCurrentImageIndex((prev) => (prev - 1 + allImages.length) % allImages.length);
  }, [allImages.length]);

  // Handle keyboard navigation
  React.useEffect(() => {
    const handleKeyPress = (e: KeyboardEvent) => {
      if (lightboxOpen) {
        if (e.key === "Escape") closeLightbox();
        if (e.key === "ArrowRight") nextImage();
        if (e.key === "ArrowLeft") prevImage();
      }
    };

    window.addEventListener("keydown", handleKeyPress);
    return () => window.removeEventListener("keydown", handleKeyPress);
  }, [lightboxOpen, nextImage, prevImage]);

  return (
    <>
      {/* Masonry-style Gallery Grid */}
      <div className="columns-1 gap-4 space-y-4 sm:columns-2 md:columns-3 lg:columns-4 xl:columns-5">
        {galleryData.map((gallery: any) => 
          gallery.images.map((item: any) => {
            if (gallery.id === "before-after") {
              return (
                <React.Fragment key={`${gallery.id}-${item.id}`}>
                  {/* Before Image */}
                  <div 
                    className="group relative break-inside-avoid cursor-pointer overflow-hidden rounded-lg shadow-md hover:shadow-xl transition-all duration-300"
                    onClick={() => openLightbox(item.beforeImage)}
                  >
                    <Image
                      src={item.beforeImage}
                      alt={`Before - ${item.title}`}
                      width={400}
                      height={300}
                      className="w-full transition-transform duration-300 group-hover:scale-105"
                    />
                    <div className="absolute inset-0 bg-black/0 transition-all duration-300 group-hover:bg-black/10" />
                    <div className="absolute left-2 top-2 rounded bg-red-500 px-2 py-1 text-xs font-bold text-white shadow-md">
                      BEFORE
                    </div>
                  </div>
                  
                  {/* After Image */}
                  <div 
                    className="group relative mt-4 break-inside-avoid cursor-pointer overflow-hidden rounded-lg shadow-md hover:shadow-xl transition-all duration-300"
                    onClick={() => openLightbox(item.afterImage)}
                  >
                    <Image
                      src={item.afterImage}
                      alt={`After - ${item.title}`}
                      width={400}
                      height={300}
                      className="w-full transition-transform duration-300 group-hover:scale-105"
                    />
                    <div className="absolute inset-0 bg-black/0 transition-all duration-300 group-hover:bg-black/10" />
                    <div className="absolute left-2 top-2 rounded bg-green-500 px-2 py-1 text-xs font-bold text-white shadow-md">
                      AFTER
                    </div>
                  </div>
                </React.Fragment>
              );
            } else {
              return (
                <div 
                  key={`${gallery.id}-${item.id}`} 
                  className="group relative break-inside-avoid cursor-pointer overflow-hidden rounded-lg shadow-md hover:shadow-xl transition-all duration-300"
                  onClick={() => openLightbox(item.image)}
                >
                  <Image
                    src={item.image}
                    alt={item.title || `Gallery image`}
                    width={400}
                    height={300}
                    className="w-full transition-transform duration-300 group-hover:scale-105"
                  />
                  <div className="absolute inset-0 bg-black/0 transition-all duration-300 group-hover:bg-black/10" />
                </div>
              );
            }
          })
        )}
      </div>

      {/* Lightbox */}
      <Lightbox
        images={allImages}
        currentIndex={currentImageIndex}
        isOpen={lightboxOpen}
        onClose={closeLightbox}
        onNext={nextImage}
        onPrev={prevImage}
      />
    </>
  );
};

export default GalleryGrid;