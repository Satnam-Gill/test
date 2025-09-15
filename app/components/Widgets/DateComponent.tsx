import React from 'react';

interface Props {
  publishedAt: string;
}

const DateComponent: React.FC<Props> = ({ publishedAt }) => {
  const formattedDate = new Date(publishedAt).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  return <div>{formattedDate}</div>;
};

export default DateComponent;
