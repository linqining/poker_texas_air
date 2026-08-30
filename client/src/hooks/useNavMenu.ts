import { useState } from 'react';

type UseNavMenuReturn = [
  boolean,
  () => void,
  () => void,
];

const useNavMenu = (): UseNavMenuReturn => {
  const [showNavMenu, setShowNavMenu] = useState(false);

  const openNavMenu = (): void => {
    document.body.style.overflow = 'hidden';
    Array.from(document.getElementsByClassName('blur-target')).forEach(
      (element) => {
        (element as HTMLElement).style.filter = 'blur(4px)';
      },
    );
    setShowNavMenu(true);
  };

  const closeNavMenu = (): void => {
    document.body.style.overflow = 'initial';
    Array.from(document.getElementsByClassName('blur-target')).forEach(
      (element) => {
        (element as HTMLElement).style.filter = 'none';
      },
    );
    setShowNavMenu(false);
  };

  return [showNavMenu, openNavMenu, closeNavMenu];
};

export default useNavMenu;
