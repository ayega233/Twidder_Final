# Module for Selenium tests

import time
import server
import unittest
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service


class TwidderTests(unittest.TestCase):
    def setUp(self):
        service = Service()
        options = webdriver.ChromeOptions()
        self.driver = webdriver.Chrome(service=service, options=options)
        #self.driver = webdriver.Chrome("drivers/chromedriver.exe")

    def test_signup(self):
        driver = self.driver
        email = server.randomToken(10) + "@gmail.com"
        password = repeat_password = "pass123"
        firstname = "Test"
        familyname = "User"
        gender = "Male"
        city = "Linkoping"
        country = "Sweden"
        driver.get("http://localhost:5000")

        email_field = driver.find_element(By.ID, "emailsignup")
        password_field = driver.find_element(By.ID, "passwordsignup")
        repeat_password_field = driver.find_element(By.ID, "repasswordsignup")
        firstname_field = driver.find_element(By.ID, "firstname")
        familyname_field = driver.find_element(By.ID, "familyname")
        gender_field = driver.find_element(By.ID, "gender")
        city_field = driver.find_element(By.ID, "city")
        country_field = driver.find_element(By.ID, "country")
        signup_button = driver.find_element(By.ID, "signup")

        email_field.send_keys(email)
        password_field.send_keys(password)
        repeat_password_field.send_keys(repeat_password)
        firstname_field.send_keys(firstname)
        familyname_field.send_keys(familyname)
        gender_field.send_keys(gender)
        city_field.send_keys(city)
        country_field.send_keys(country)

        signup_button.send_keys(Keys.RETURN)
        time.sleep(5)
        signup_message = driver.find_element(By.XPATH, "//span[@id='message']").text
        # print(signup_message)
        assert signup_message == "Successfully created a new user."

    def test_sign_in(self):
        driver = self.driver
        email = "yemi@gmail.com"
        password = "123456"
        driver.get("http://localhost:5000")
        
        email_field = driver.find_element(By.ID, "login_email")
        password_field = driver.find_element(By.ID, "login_password")
        login_button = driver.find_element(By.ID, "login_submit")

        email_field.send_keys(email)
        password_field.send_keys(password)

        login_button.send_keys(Keys.RETURN)
        time.sleep(5)
        web_view = driver.find_element(By.XPATH, "/html/body/div/div/div[2]/div")
        #signin_message = driver.find_element(By.ID, "message").text
        # print(signin_message)
        self.assertTrue(web_view.is_displayed())

    def test_post_message(self):
        driver = self.driver
        email = "yemi@gmail.com"
        password = "123456"
        driver.get("http://localhost:5000")
        email_field = driver.find_element(By.ID, "login_email")
        password_field = driver.find_element(By.ID, "login_password")
        login_button = driver.find_element(By.ID, "login_submit")
        email_field.send_keys(email)
        password_field.send_keys(password)
        login_button.send_keys(Keys.RETURN)
        time.sleep(5)

        message1 = "Hola! This message is from Selenium"

        post_message_field = driver.find_element(By.ID, "wall_thoughts")
        post_button = driver.find_element(By.ID, "post_wall")

        post_message_field.send_keys(message1)
        post_button.send_keys(Keys.RETURN)
        time.sleep(5)
        post_message = driver.find_element(By.ID, "theTextarea").text
        # print(post_message)

        self.assertIn(message1, post_message)

    def test_search_user(self):
        driver = self.driver
        email = "yemi@gmail.com"
        password = "123456"
        driver.get("http://localhost:5000")
        email_field = driver.find_element(By.ID, "login_email")
        password_field = driver.find_element(By.ID, "login_password")
        login_button = driver.find_element(By.ID, "login_submit")
        email_field.send_keys(email)
        password_field.send_keys(password)
        login_button.send_keys(Keys.RETURN)
        time.sleep(5)

        driver.find_element(By.ID, "tabs3").send_keys(Keys.RETURN)
        email_field = driver.find_element(By.ID, "search_member")
        search_button = driver.find_element(By.ID, "search_button")

        email2 = "aaa@gmail.com"
        email_field.send_keys(email2)

        search_button.send_keys(Keys.RETURN)
        time.sleep(5)
        search_user = driver.find_element(By.XPATH, "//*[@id='email_output_2']").text
        # print(search_message)

        assert search_user == email2

    def test_post_message_to_others(self):
        driver = self.driver
        email = "yemi@gmail.com"
        password = "123456"
        driver.get("http://localhost:5000")
        email_field = driver.find_element(By.ID, "login_email")
        password_field = driver.find_element(By.ID, "login_password")
        login_button = driver.find_element(By.ID, "login_submit")
        email_field.send_keys(email)
        password_field.send_keys(password)
        login_button.send_keys(Keys.RETURN)
        time.sleep(5)

        message2 = "Bonjour from Selenium!"

        driver.find_element(By.ID, "tabs3").send_keys(Keys.RETURN)
        email_field = driver.find_element(By.ID, "search_member")
        search_button = driver.find_element(By.ID, "search_button")

        email2 = "aaa@gmail.com"
        email_field.send_keys(email2)

        search_button.send_keys(Keys.RETURN)
        time.sleep(5)

        post_message_field = driver.find_element(By.ID, "wall_thoughts_2")
        post_button = driver.find_element(By.ID, "post_wall_2")

        post_message_field.send_keys(message2)

        post_button.send_keys(Keys.RETURN)
        time.sleep(5)
        post_others_message = driver.find_element(By.ID, "theTextarea_2").text
        # print(post_others_message)

        self.assertIn(message2, post_others_message)

    def tearDown(self):
        self.driver.close()


if __name__ == '__main__':
    unittest.main()