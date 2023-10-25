import time

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import re
import datetime
from flask import Flask, render_template, request, redirect, session, Response
from flask_session import Session
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import hashlib
import requests
from beebotte import *


class Beebotte:
    def __init__(self):
        self._mi_API_KEY = 'VdCe9h2HsVBskqqu2NWk2TA1'
        self._mi_secret_KEY = 'vBIIRCj9ZTlkuoPPaOeqkf9Jyvj9tEkb'
        self._gold_channel_name = 'gold_info'
        self._user_channel_name = 'user_info'
        self._hostname = 'api.beebotte.com'
        self._historico_oro = {}
        self._bbt = BBT(self._mi_API_KEY, self._mi_secret_KEY, hostname=self._hostname)

    def escribir_oro(self, valor_oro):
        self._bbt.write("gold_info", "time", datetime.datetime.now().isoformat())
        self._bbt.write("gold_info","gold_info", valor_oro)
    def _leer_oro(self):
        self._historico_oro = self._bbt.read("gold_info", "gold_info", limit=5)
        actual_time = self._bbt.read("gold_info", "time", limit=5)

    def obtain_last_gold(self):
        obtained = self._bbt.read(channel= self._gold_channel_name, resource=self._gold_channel_name, limit=1)
        return obtained[0].get('data')

    def obtain_gold_average(self):
        total_value = 0
        obtained = self._bbt.read(channel=self._gold_channel_name, resource=self._gold_channel_name, limit=750)
        for iter in range(len(obtained)):
            total_value = total_value + (obtained[iter].get('data'))
        average = total_value / len(obtained)
        return average

class Web:
    def __init__(self):
        self._app = Flask(__name__)
        self._app.config['SESSION_TYPE'] = 'filesystem'  # Puedes elegir otras opciones como 'redis', 'mongodb', etc.
        self._app.config['SESSION_PERMANENT'] = False  # Las sesiones no son permanentes (se almacenarán en cookies)
        self._app.config['SESSION_USE_SIGNER'] = True  # Activa la firma de cookies (opcional para mayor seguridad)
        self._app.secret_key = 'tu_clave_secreta'  # Define una clave secreta para firmar cookies

        Session(self._app)
        self.mi_BBDD = BBDD()
        self.mi_Beebotte = Beebotte()
        self._registrado = 0
        self._numero_peticiones_local = 0
        self._numero_peticiones_nube = 0
        self._media_base_datos_local = 0
        self._media_base_datos_nube = 0
        self._umbral_solicitado = 0

        @self._app.route('/registrado', methods=['GET', 'POST'])
        def registrado():
            if request.method == 'POST':
                if 'limit' in request.form:
                    limit = request.form['limit']
                    try:
                        session['nonumero'] = 0
                        session['limite'] = float(limit)
                        session['limite_solicitado'] = 1

                    except ValueError:
                        session['nonumero'] = 1
                        session['limite_solicitado'] = 0
                if 'umbral' in request.form:
                    umbral = request.form['umbral']
                    try:
                        numero = float(umbral)
                        self.mi_BBDD.obtener_5_ultimos(numero)
                        session['umbral5solicitado'] = 1
                        session['nonumero'] = 0
                        valores = [str(valor) for valor in self.mi_BBDD.ultimos_5_valores.values()]
                        resultado = " ".join(valores)
                        session['umbraless'] = resultado
                    except ValueError:
                        session['nonumero'] = 1
                if 'media' in request.form:
                    media = request.form['media']
                    if media == "logout":
                        session['nonumero'] = 0
                        session["intento_erroneo"] = 0
                        session["registrado"] = 0
                        session["media_nube_solicitada"] = 0
                        session["umbral5solicitado"] = 0
                        session["media_local_solicitada"] = 0
                        valor_actual_oro = self.mi_BBDD.obtain_last_gold()
                        return render_template('principal.html', precio_oro=valor_actual_oro)
                    if media == "local":
                        session["media_local_solicitada"] = 1
                        self._numero_peticiones_local += 1
                        self.mi_BBDD.nuevo_click(self._numero_peticiones_local, local=1)
                        self._media_base_datos_local = self.mi_BBDD.obtain_gold_average()
                    if media == "external":
                        session["media_nube_solicitada"] = 1
                        self._numero_peticiones_nube += 1
                        self.mi_BBDD.nuevo_click(self._numero_peticiones_nube, local=0)
                        self._media_base_datos_nube = self.mi_Beebotte.obtain_gold_average()
                    if media == "graficas":
                        session["grafica_solicitada"] = 1

            clicks_external = self.mi_BBDD.leer_numero_clicks(0)
            clicks_local = self.mi_BBDD.leer_numero_clicks(1)
            return render_template('registrado.html', valor_media_local=self._media_base_datos_local,valor_media_nube=self._media_base_datos_nube, clicks_local=clicks_local,clicks_external=clicks_external)


        @self._app.route('/', methods=['GET', 'POST'])
        def pagina_principal():
            valor_actual_oro = self.mi_BBDD.obtain_last_gold()
            session['limite_solicitado'] = 0
            session['limite'] = 0
            if request.method == 'POST':
                media = request.form['media']
                if media == "registro":
                    session['limite_solicitado'] = 0
                    session['umbral5solicitado'] = 0
                    session["media_nube_solicitada"] = 0
                    session["media_local_solicitada"] = 0
                    session["intento_media_nube"] = 0
                    session["intento_media_local"] = 0
                    return redirect('/registro')
                elif media == "local":
                    session["intento_media_local"] = 1
                elif media == "external":
                    session["intento_media_nube"] = 1

            return render_template('principal.html',precio_oro=valor_actual_oro)

        @self._app.route('/sse')
        def sse():
            def event_stream(limite_solicitado, limite):
                while True:
                    time.sleep(1)  # Simula una actualización cada segundo
                    if limite_solicitado == 1:
                        valor_actual = self.mi_BBDD.obtain_last_gold()
                        if limite < valor_actual:
                            yield f"data: Su valor {limite} no supera el valor actual {valor_actual}\n\n"
                        else:
                            yield f"data: Su valor {limite} supera el valor actual {valor_actual}\n\n"
                    else:
                        yield f"data: \n\n"

            limite = session.get('limite', 0)
            limite_solicitado = session.get('limite_solicitado', 0)
            return Response(event_stream(limite_solicitado, limite), content_type='text/event-stream')

        @self._app.route('/registro', methods=['GET', 'POST'])
        def registro():
            if request.method == 'POST':
                email = request.form['email']
                username = request.form['username']
                password = request.form['password']
                inscrito = self.mi_BBDD.search_logged(email,password)
                if inscrito == 'emailypassn':
                    session["intento_erroneo"] = 1
                    return redirect('/')
                elif inscrito == 'emailnpassn':
                    self.mi_BBDD.login_man(email=email, password=password, username=username)
                    session["username"] = username
                    session["registrado"] = 1
                    return redirect('/registrado')
                else:
                    session["intento_erroneo"] = 0
                    session["username"] = username
                    session["registrado"] = 1
                    return redirect('/registrado')

            return render_template('registro.html')


        self._app.run(host='0.0.0.0', port=8080,debug=True)
class BBDD:
    def __init__(self):
        self._es = Elasticsearch([{'host':'localhost', 'port': 9200, 'scheme':'http'}])
        self._es.ping()
        self._gold_index_name = 'gold_index'
        self._login_index_name = 'login_index'
        self._clicks_index_name_local = 'clicks_index_local'
        self._clicks_index_name_external = 'clicks_index_external'
        self._historico_oro = {}
        self._historico_clicks = {}
        self.ultimos_5_valores = {}
        self._secret_seed = b'fHS\x07\x9f{\xac\x06\x98\x87v`(\x89s\xaa'

    def obtener_5_ultimos(self, umbral):
        self.ultimos_5_valores = {}
        self._actualizar_oro()
        contador = 0
        lista_de_claves = list(self._historico_oro.keys())
        for i in range(len(self._historico_oro)):
            ultima_clave = lista_de_claves[-i-1]
            ultimo_elemento = self._historico_oro[ultima_clave]
            if ultimo_elemento['valor'] > umbral:
                self.ultimos_5_valores[contador] = ultimo_elemento['valor']
                contador += 1
                if contador > 4:
                    break
        if self.ultimos_5_valores is None:
            self.ultimos_5_valores = 0


    def leer_numero_clicks(self, local):
        if local == 1:
            indexo = self._clicks_index_name_local
        else:
            indexo = self._clicks_index_name_external

        query = {
            "query":{
                "match_all":{}
            }
        }
        contador = 0
        for hit in scan(self._es, index=indexo, query=query):
            documento = hit['_source']
            self._historico_clicks[contador] = documento
            contador += 1
        try:
            ultima_clave = list(self._historico_clicks.keys())[-1]
            ultimo_valor = self._historico_clicks[ultima_clave]
            return ultimo_valor.get('clicks')
        except:
            return 0



    def nuevo_click(self, numero_clicks, local):
        if local == 1:
            indexo = self._clicks_index_name_local
        else:
            indexo = self._clicks_index_name_external

        data_to_index = {'clicks': numero_clicks}
        self._es.index(index=indexo, document=data_to_index)


    def login_man(self, email, password, username):
        password_encrypted = password.encode('utf-8') + self._secret_seed
        hashed_password = hashlib.sha256(password_encrypted).hexdigest()
        data_to_index = {'email': email,
                         'password': hashed_password,
                         'username': username}
        self._es.index(index='login_index', document=data_to_index)


    def search_logged(self, email,password):
        query = {
            "query":{
                "match_all":{}
            }
        }
        for hit in scan(self._es, index= self._login_index_name, query=query):
            documento = hit['_source']
            if documento is None:
                return 'emailnpassn'
            if documento['email'] == email:
                password_encrypted = password.encode('utf-8') + self._secret_seed
                hashed_password = hashlib.sha256(password_encrypted).hexdigest()
                if documento['password'] == hashed_password:
                    return 'emailypassy'
                return 'emailypassn'
        return 'emailnpassn'

    def escribir_oro(self, valor_oro):
        data_to_index = {'fecha':datetime.datetime.now().isoformat(),
                         'valor':valor_oro}

        self._es.index(index=self._gold_index_name, document=data_to_index)

    def _actualizar_oro(self):
        query = {
            "query":{
                "match_all":{}
            }
        }
        contador = 0
        for hit in scan(self._es, index= self._gold_index_name, body= query):
            documento = hit['_source']
            self._historico_oro[contador] = documento
            contador += 1
        if self._historico_oro is None:
            self._historico_oro[0] = 0


    def obtain_last_gold(self):
        self._actualizar_oro()
        lista_de_claves = list(self._historico_oro.keys())
        ultima_clave = lista_de_claves[-1]
        ultimo_elemento = self._historico_oro[ultima_clave]
        return ultimo_elemento.get('valor')

    def obtain_gold_average(self):
        average = 0
        query = {
            "query":{
                "match_all":{}
            }
        }
        contador = 0
        for hit in scan(self._es, index=self._gold_index_name, query=query):
            documento = hit['_source']
            average = average + documento.get('valor')
            contador += 1

        if contador == 0:
            return 0
        return average/contador



class Scrapper:
    def __init__(self,url):
        try:
            chrome_options = Options()
            self.valor_oro = 0
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--log-level=3')
            self._driver = webdriver.Chrome(options=chrome_options)

            self._url = url

        except:
            print("jo")

    def obtain_valor_oro(self):
        self._driver.get(self._url)
        try:
            html_code = self._driver.page_source
            patron = r'text-5xl[^>]*>([^<]+)<'
            #patron = r'#232526]">(\d{1,3}(?:\.\d{3})*(?:,\d+))</div>'
            resultado = re.search(patron, html_code)
            elemento = resultado.group(1)
            self.valor_oro = int(elemento[0]) * 1000 + int(elemento[2]) * 100 + int(elemento[3]) * 10 + int(
                elemento[4]) + int(elemento[6]) * 0.1 + int(elemento[7]) * 0.01
        except Exception as e:
            print('Error:', e)





