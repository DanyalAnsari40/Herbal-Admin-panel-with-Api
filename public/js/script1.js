 document.addEventListener('DOMContentLoaded', function() {
            const doors = document.querySelectorAll('.door');
            const resultContainer = document.getElementById('result');
            const selectedDoorSpan = document.getElementById('selected-door');
            const finalPriceSpan = document.getElementById('final-price');
            const tryAgainBtn = document.getElementById('try-again');
            
            const basePrice = 11999;
            const discountPercent = 50;
            
            let gamePlayed = false;
            
            doors.forEach(door => {
                door.addEventListener('click', function() {
                    if (gamePlayed) return;
                    
                    gamePlayed = true;
                    const doorNumber = this.getAttribute('data-door');
                    this.classList.add('selected');
                    
                    // Disable other doors
                    doors.forEach(d => {
                        if (d !== this) {
                            d.style.opacity = '0.5';
                            d.style.pointerEvents = 'none';
                        }
                    });
                    
                    // Show result after animation
                    setTimeout(() => {
                        showResult(doorNumber);
                    }, 1000);
                });
            });
            
            function showResult(doorNumber) {
                const discountAmount = (basePrice * discountPercent) / 100;
                const finalPrice = basePrice - discountAmount;
                
                selectedDoorSpan.textContent = doorNumber;
                finalPriceSpan.textContent = 'PKR ' + finalPrice.toFixed(2);
                
                resultContainer.style.display = 'block';
            }
            
            tryAgainBtn.addEventListener('click', function() {
                // Reset game
                doors.forEach(door => {
                    door.classList.remove('selected');
                    door.style.opacity = '1';
                    door.style.pointerEvents = 'auto';
                    door.style.transform = 'rotateY(0)';
                });
                
                resultContainer.style.display = 'none';
                gamePlayed = false;
            });
        });