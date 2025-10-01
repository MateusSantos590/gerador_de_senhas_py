// Espera o conteúdo da página carregar antes de executar o script
document.addEventListener('DOMContentLoaded', () => {

    const certificadoItems = document.querySelectorAll('.certificado-item');
    const modal = document.getElementById('certificateModal');
    const modalCertificateName = document.getElementById('modalCertificateName');
    const qrcodeContainer = document.getElementById('qrcode');
    const closeButton = modal.querySelector('.close-button');
    let qrcode = null; // Variável para guardar a instância do QR Code

    // Função para abrir o modal
    const openModal = (name, url) => {
        // Atualiza o nome do certificado no modal
        modalCertificateName.textContent = name;

        // Limpa o QR code anterior
        qrcodeContainer.innerHTML = '';

        // Cria um novo QR Code
        qrcode = new QRCode(qrcodeContainer, {
            text: url,
            width: 200,
            height: 200,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.H
        });

        // Mostra o modal
        modal.classList.add('active');
    };

    // Função para fechar o modal
    const closeModal = () => {
        modal.classList.remove('active');
        // Opcional: limpa o QR code ao fechar para liberar memória
        if (qrcode) {
            qrcode.clear();
            qrcodeContainer.innerHTML = '';
        }
    };

    // Adiciona evento de clique para cada item de certificado
    certificadoItems.forEach(item => {
        item.addEventListener('click', () => {
            const name = item.querySelector('h3').textContent;
            const url = item.dataset.certificateUrl;
            openModal(name, url);
        });
    });

    // Eventos para fechar o modal
    closeButton.addEventListener('click', closeModal);
    modal.addEventListener('click', (event) => {
        if (event.target === modal) {
            closeModal();
        }
    });
});