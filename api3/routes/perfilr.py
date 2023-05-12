from flask import Flask, jsonify, request, Blueprint
from flask_cors import  cross_origin

from controllers.perfilc import *

perfil = Blueprint('perfil', __name__)

con_perfil = Perfilc()

@perfil.route('/perfiles', methods=['GET'])
@cross_origin() 
def consultar_perfiles():
    return con_perfil.consultar_perfiles()

@perfil.route('/consultar/perfil/id', methods=['GET'])
@cross_origin() 
def consultar_perfil_id():
    return con_perfil.consultar_perfil_id()

