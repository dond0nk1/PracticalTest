const { Builder, By, until } = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const assert = require('assert');

describe('Secure Form Integration Tests', function() {
    let driver;
    const baseUrl = process.env.TEST_BASE_URL || 'http://localhost';

    before(async function() {
        console.log('Setting up Selenium WebDriver...');
        const options = new chrome.Options();
        options.addArguments('--headless');
        options.addArguments('--no-sandbox');
        options.addArguments('--disable-dev-shm-usage');
        options.addArguments('--disable-gpu');
        options.addArguments('--window-size=1920,1080');
        
        // Use remote WebDriver if SELENIUM_HOST is set (for CI)
        if (process.env.SELENIUM_HOST) {
            console.log('Using remote Selenium server:', process.env.SELENIUM_HOST);
            driver = await new Builder()
                .forBrowser('chrome')
                .setChromeOptions(options)
                .usingServer(process.env.SELENIUM_HOST)
                .build();
        } else {
            console.log('Using local Chrome driver');
            driver = await new Builder()
                .forBrowser('chrome')
                .setChromeOptions(options)
                .build();
        }
        console.log('WebDriver setup complete');
    });

    after(async function() {
        if (driver) {
            console.log('Closing WebDriver...');
            await driver.quit();
        }
    });

    it('should load the secure form page successfully', async function() {
        console.log('Testing page load...');
        await driver.get(baseUrl);
        const title = await driver.getTitle();
        assert.strictEqual(title, 'Secure Form', 'Page title should be "Secure Form"');
        console.log('✓ Page loaded successfully');
    });

    it('should have all required form elements present', async function() {
        console.log('Testing form elements...');
        await driver.get(baseUrl);
        
        const form = await driver.findElement(By.id('secureForm'));
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        const errorDiv = await driver.findElement(By.id('errorMessage'));
        
        assert(form, 'Form element should be present');
        assert(input, 'Input field should be present');
        assert(submitButton, 'Submit button should be present');
        assert(errorDiv, 'Error message div should be present');
        
        // Check input attributes
        const placeholder = await input.getAttribute('placeholder');
        const maxLength = await input.getAttribute('maxlength');
        assert.strictEqual(placeholder, 'Type your message here...', 'Input should have correct placeholder');
        assert.strictEqual(maxLength, '200', 'Input should have maxlength of 200');
        
        console.log('✓ All form elements are present and configured correctly');
    });

    it('should show error message for empty input submission', async function() {
        console.log('Testing empty input validation...');
        await driver.get(baseUrl);
        
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        await submitButton.click();
        
        // Wait for error message to appear
        await driver.wait(until.elementTextIs(
            driver.findElement(By.id('errorMessage')), 
            'Please enter a message.'
        ), 5000);
        
        const errorMessage = await driver.findElement(By.id('errorMessage'));
        const errorText = await errorMessage.getText();
        assert.strictEqual(errorText, 'Please enter a message.', 'Should show empty input error');
        console.log('✓ Empty input validation works correctly');
    });

    it('should block XSS script tag injection attempts', async function() {
        console.log('Testing XSS script protection...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        // Try XSS attack with script tag
        const xssPayload = '<script>alert("XSS")</script>';
        await input.clear();
        await input.sendKeys(xssPayload);
        await submitButton.click();
        
        // Wait and check that input is cleared (XSS blocked)
        await driver.sleep(1500);
        const inputValue = await input.getAttribute('value');
        assert.strictEqual(inputValue, '', 'XSS script should be blocked and input cleared');
        console.log('✓ XSS script injection blocked successfully');
    });

    it('should block XSS iframe injection attempts', async function() {
        console.log('Testing XSS iframe protection...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        // Try XSS attack with iframe
        const iframePayload = '<iframe src="javascript:alert(1)"></iframe>';
        await input.clear();
        await input.sendKeys(iframePayload);
        await submitButton.click();
        
        await driver.sleep(1500);
        const inputValue = await input.getAttribute('value');
        assert.strictEqual(inputValue, '', 'XSS iframe should be blocked and input cleared');
        console.log('✓ XSS iframe injection blocked successfully');
    });

    it('should block XSS event handler injection attempts', async function() {
        console.log('Testing XSS event handler protection...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        // Try XSS attack with event handler
        const eventPayload = '<img src=x onerror=alert("XSS")>';
        await input.clear();
        await input.sendKeys(eventPayload);
        await submitButton.click();
        
        await driver.sleep(1500);
        const inputValue = await input.getAttribute('value');
        assert.strictEqual(inputValue, '', 'XSS event handler should be blocked and input cleared');
        console.log('✓ XSS event handler injection blocked successfully');
    });

    it('should block SQL injection DROP TABLE attempts', async function() {
        console.log('Testing SQL injection DROP protection...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        // Try SQL injection attack
        const sqlPayload = "'; DROP TABLE users; --";
        await input.clear();
        await input.sendKeys(sqlPayload);
        await submitButton.click();
        
        await driver.sleep(1500);
        const inputValue = await input.getAttribute('value');
        assert.strictEqual(inputValue, '', 'SQL injection should be blocked and input cleared');
        console.log('✓ SQL DROP injection blocked successfully');
    });

    it('should block SQL injection UNION SELECT attempts', async function() {
        console.log('Testing SQL UNION SELECT protection...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        // Try UNION SELECT attack
        const unionPayload = "' UNION SELECT password FROM users --";
        await input.clear();
        await input.sendKeys(unionPayload);
        await submitButton.click();
        
        await driver.sleep(1500);
        const inputValue = await input.getAttribute('value');
        assert.strictEqual(inputValue, '', 'UNION SELECT should be blocked and input cleared');
        console.log('✓ SQL UNION SELECT injection blocked successfully');
    });

    it('should block SQL injection authentication bypass attempts', async function() {
        console.log('Testing SQL authentication bypass protection...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        // Try authentication bypass
        const bypassPayload = "admin' OR '1'='1' --";
        await input.clear();
        await input.sendKeys(bypassPayload);
        await submitButton.click();
        
        await driver.sleep(1500);
        const inputValue = await input.getAttribute('value');
        assert.strictEqual(inputValue, '', 'SQL authentication bypass should be blocked and input cleared');
        console.log('✓ SQL authentication bypass blocked successfully');
    });

    it('should redirect to result page with valid input', async function() {
        console.log('Testing valid input submission...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        // Enter valid input
        const validMessage = 'Hello World! This is a valid message.';
        await input.clear();
        await input.sendKeys(validMessage);
        await submitButton.click();
        
        // Should redirect to result page
        await driver.wait(until.urlContains('result.html'), 10000);
        const currentUrl = await driver.getCurrentUrl();
        assert(currentUrl.includes('result.html'), 'Should redirect to result page with valid input');
        console.log('✓ Valid input redirects to result page successfully');
    });

    it('should display sanitized message on result page', async function() {
        console.log('Testing message display on result page...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        const testMessage = 'Test message for display validation';
        await input.clear();
        await input.sendKeys(testMessage);
        await submitButton.click();
        
        // Wait for redirect and check result page
        await driver.wait(until.urlContains('result.html'), 10000);
        
        // Wait for message to load
        await driver.wait(until.elementLocated(By.id('userMessage')), 5000);
        const userMessage = await driver.findElement(By.id('userMessage'));
        const displayedText = await userMessage.getText();
        assert.strictEqual(displayedText, testMessage, 'Sanitized message should be displayed correctly');
        console.log('✓ Message displayed correctly on result page');
    });

    it('should have functional return button on result page', async function() {
        console.log('Testing return button functionality...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        await input.clear();
        await input.sendKeys('Test for return button functionality');
        await submitButton.click();
        
        await driver.wait(until.urlContains('result.html'), 10000);
        
        // Check return button exists and has correct text
        const returnButton = await driver.findElement(By.css('button'));
        const buttonText = await returnButton.getText();
        assert.strictEqual(buttonText, 'Return to Home Page', 'Return button should have correct text');
        
        // Test return functionality
        await returnButton.click();
        await driver.wait(until.urlContains('index.html'), 10000);
        const finalUrl = await driver.getCurrentUrl();
        assert(finalUrl.includes('index.html') || finalUrl.endsWith('/'), 'Should return to home page');
        console.log('✓ Return button works correctly');
    });

    it('should handle multiple security attacks in sequence', async function() {
        console.log('Testing multiple security attacks...');
        await driver.get(baseUrl);
        
        const input = await driver.findElement(By.id('userInput'));
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        const attacks = [
            '<script>alert("XSS1")</script>',
            "'; DELETE FROM users; --",
            '<img src=x onerror=alert(1)>',
            "' OR 1=1 --",
            'javascript:alert("XSS2")'
        ];
        
        // Test each attack
        for (const attack of attacks) {
            await input.clear();
            await input.sendKeys(attack);
            await submitButton.click();
            await driver.sleep(1000);
            
            const inputValue = await input.getAttribute('value');
            assert.strictEqual(inputValue, '', `Attack "${attack}" should be blocked`);
        }
        
        console.log('✓ All security attacks blocked successfully');
    });
});