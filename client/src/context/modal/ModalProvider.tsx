import React, { useState, useEffect } from 'react';
import ModalContext from './modalContext';
import Modal from '../../components/modals/Modal';
import { ModalData, ModalContextType } from './modalContext';

/* 占位初始值：仅在 showModal=false 时存在，弹窗打开前总会被 openModal 覆盖 */
const emptyModalData: ModalData = {
  children: () => null,
  headingText: '',
  btnText: '',
  btnCallBack: () => {},
  onCloseCallBack: () => {},
};

interface ModalProviderProps {
  children: React.ReactNode;
}

const ModalProvider: React.FC<ModalProviderProps> = ({ children }) => {
  const [showModal, setShowModal] = useState(false);
  const [modalData, setModalData] = useState<ModalData>(emptyModalData);

  useEffect(() => {
    const layoutWrapper = document.getElementById('layout-wrapper');

    if (showModal) {
      document.body.style.overflow = 'hidden';

      if (layoutWrapper) {
        layoutWrapper.style.filter = 'blur(4px)';
        layoutWrapper.style.pointerEvents = 'none';
        layoutWrapper.tabIndex = -1;
      }
    } else {
      document.body.style.overflow = 'initial';

      if (layoutWrapper) {
        layoutWrapper.style.filter = 'none';
        layoutWrapper.style.pointerEvents = 'all';
      }
    }
  }, [showModal]);

  const closeModal = () => setShowModal(false);

  const openModal: ModalContextType['openModal'] = (
    children,
    headingText,
    btnText,
    btnCallBack = closeModal,
    onCloseCallBack = closeModal,
  ) => {
    setModalData({
      children,
      headingText,
      btnText,
      btnCallBack,
      onCloseCallBack,
    });

    setShowModal(true);
  };

  return (
    <ModalContext.Provider
      value={{ showModal, modalData, openModal, closeModal }}
    >
      {children}
      {showModal && (
        <Modal
          headingText={modalData.headingText}
          btnText={modalData.btnText}
          onClose={modalData.onCloseCallBack}
          onBtnClicked={modalData.btnCallBack}
        >
          {modalData.children()}
        </Modal>
      )}
    </ModalContext.Provider>
  );
};

export default ModalProvider;
