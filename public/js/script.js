// // import trackLoc from './api/track_product.json' assert { type: "json" };
// // No import if using fetch (modules not supported by all browsers with import assert)
// const trackBtn = document.querySelector('.btn-track');
// // const usernameInput = document.querySelector('#username');
// // const passwordInput = document.querySelector('#password');
// const p_id_Input = document.querySelector('#p_id');
// const modalOverlay = document.querySelector('#modalOverlay');
// const closeModalBtn = document.querySelector('#closeModal');
// const trackingHeader = document.querySelector('#trackingHeader');
// const timeline = document.querySelector('#timeline');
// const service = document.querySelector('#service');

// // Fetch and track logic
// trackBtn.addEventListener('click', async () => {
//   // const username = usernameInput.value.trim();
//   const selected_Service = service.value.trim();
//   const p_id = p_id_Input.value.trim();


//   // if (username !== 'user' || password !== '123') {
//   //   alert('Invalid username or password');
//   //   return;
//   // }
//             //! Checking the servive type?
  
//   const serviceUrlMap = {
//     'TCS': '/api/track_product.json',
//     'N&P': '/api/n_p.json',
//     'LEOPARDS': '/api/n_p.json',
//     'PAK-POST': null
//   };

//   const url = serviceUrlMap[selected_Service];

//   if (!url) {
//     alert('Selected service is not supported for tracking.');
//     return;
//   }
    
       
//   try {
//     const response = await fetch(url);
//     const trackLoc = await response.json();

//     const match = trackLoc.find(item =>
//       item.tracking_Details[0].Consignment === p_id
//     );

//     if (!match) {
//       alert('No consignment found with that number');
//       return;
//     }

//     const trackingDetails = match.tracking_Details[0];
//     const steps = trackingDetails.Details;

//     trackingHeader.innerHTML = `
//       <h3>Status: <span style="color: ${getStatusColor(trackingDetails.CNStatus)}">${trackingDetails.CNStatus}</span></h3>
//       <div class="route">
//         <span>From: ${trackingDetails.Origin}</span>
//         <i class="fas fa-arrow-right"></i>
//         <span>To: ${trackingDetails.Destination}</span>
//       </div>
//       <p>Consignment: ${trackingDetails.Consignment}</p>
//     `;

//     createTimeline(steps);
//     showModal();

//   } catch (error) {
//     alert('Error fetching tracking data.');
//     console.error(error);
//   }
// });

// // Modal handlers
// function showModal() {
//   modalOverlay.classList.add('active');
//   document.body.style.overflow = 'hidden';
// }
// function hideModal() {
//   modalOverlay.classList.remove('active');
//   document.body.style.overflow = 'auto';
// }
// modalOverlay.addEventListener('click', (e) => {
//   if (e.target === modalOverlay) hideModal();
// });
// closeModalBtn.addEventListener('click', hideModal);

// // Create timeline UI
// function createTimeline(steps) {
//   timeline.innerHTML = '';
//   steps.forEach((step, index) => {
//     const timelineItem = document.createElement('div');
//     timelineItem.className = `timeline-item ${index === steps.length - 1 ? 'current' : ''}`;
//     timelineItem.style.animationDelay = `${index * 0.2}s`;

//     timelineItem.innerHTML = `
//       <h4>${step.Status}</h4>
//       <p><i class="fas fa-map-marker-alt"></i> ${step.Location}</p>
//       <p><i class="fas fa-clock"></i> ${step.DateTime}</p>
//     `;
//     timeline.appendChild(timelineItem);
//   });
// }

// // Status color logic
// function getStatusColor(status) {
//   switch (status) {
//     case 'Delivered': return '#4CAF50';
//     case 'In Transit': return '#2196F3';
//     case 'Out for Delivery': return '#FF9800';
//     case 'Processing': return '#9C27B0';
//     default: return '#673AB7';
//   }
// }

// // Input icon and label animation
// document.querySelectorAll('.form-group.floating input').forEach(input => {
//   input.addEventListener('focus', () => {
//     input.parentElement.querySelector('i').style.color = 'var(--primary)';
//     input.parentElement.querySelector('label').style.color = 'var(--primary)';
//   });
//   input.addEventListener('blur', () => {
//     if (!input.value) {
//       input.parentElement.querySelector('i').style.color = 'var(--gray)';
//       input.parentElement.querySelector('label').style.color = 'var(--gray)';
//     }
//   });
// });

const trackBtn = document.querySelector('.btn-track');
const p_id_Input = document.querySelector('#p_id');
const modalOverlay = document.querySelector('#modalOverlay');
const modalContent = document.querySelector('#modalContent');
const closeModalBtn = document.querySelector('#closeModal');
const service = document.querySelector('#service');

trackBtn.addEventListener('click', async (e) => {
  e.preventDefault();
  runTracking();
});

function runTracking() {
  const selected_Service = service.value.trim();
  const p_id = p_id_Input.value.trim();

  if (!selected_Service || !p_id) {
    alert("Please select service and enter tracking ID.");
    return;
  }

  if (selected_Service === 'TCS') {
    const trackURL = `https://www.tcsexpress.com/track/${p_id}`;
    showIframePopup(trackURL);
    return;
  }
  if (selected_Service === 'LEOPARDS') {
    const trackURL = `http://www.leopardscourier.com/shipment_tracking?cn_number=${p_id}`;
    showIframePopup(trackURL);
    return;
  }
  if (selected_Service === 'M&P') {
    const trackURL = `https://www.mulphilog.com/tracking/${p_id}?_token=UwsLwRDWIxO81neG7M6saftVOAWm6aXLRRqSLDtU&consignment=${p_id}`;
    showIframePopup(trackURL);
    return;
  }

  alert("Selected service is not supported yet.");
}

function showIframePopup(url) {
  modalContent.innerHTML = `<iframe src="${url}" width="100%" height="600px" style="border:0;"></iframe>`;
  modalOverlay.classList.add('active');
  document.body.style.overflow = 'hidden';
}

closeModalBtn.addEventListener('click', () => {
  modalOverlay.classList.remove('active');
  modalContent.innerHTML = '';
  document.body.style.overflow = 'auto';
});

// ------------------
// Enable icon and label animations
document.querySelectorAll('.form-group.floating input').forEach(input => {
  input.addEventListener('focus', () => {
    input.parentElement.querySelector('i').style.color = 'var(--primary)';
    input.parentElement.querySelector('label').style.color = 'var(--primary)';
  });
  input.addEventListener('blur', () => {
    if (!input.value) {
      input.parentElement.querySelector('i').style.color = 'var(--gray)';
      input.parentElement.querySelector('label').style.color = 'var(--gray)';
    }
  });
});

// ------------------
// Allow auto-fill if navigated with ?service=TCS&p_id=123
window.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const serviceParam = params.get('service');
  const idParam = params.get('p_id');

  if (serviceParam) {
    const option = Array.from(service.options).find(opt => opt.value.toLowerCase() === serviceParam.toLowerCase());
    if (option) option.selected = true;
  }
  if (idParam) {
    p_id_Input.value = idParam;
  }

  if (serviceParam && idParam) {
    // runTracking();
  }
});
