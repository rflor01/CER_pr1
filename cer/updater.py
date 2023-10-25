import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import re
import datetime
from flask import Flask, render_template, request, redirect
from elasticsearch import Elasticsearch
import hashlib
import requests


from cerclasses import Scrapper, Beebotte, BBDD

if __name__ == '__main__':
    mi_Scrapper = Scrapper('http://es.investing.com/commodities/gold')
    mi_BBDD = BBDD()
    mi_Beebotte = Beebotte()
    print("Comenzando a guardar datos en el servidor")

    while(1):
        print("Escribiendo el dato actual del oro")
        mi_Scrapper.obtain_valor_oro()
        print(mi_Scrapper.valor_oro)
        mi_BBDD.escribir_oro(mi_Scrapper.valor_oro)
        mi_Beebotte.escribir_oro(mi_Scrapper.valor_oro)
        time.sleep(120)