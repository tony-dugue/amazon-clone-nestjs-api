## Présentation du projet
***

Test d'application de e-commerce inspiré du site Amazon (RESTful API) en utilisant 
le framework backend NESTJS avec une authentification JWT et l'utilisation d'une 
base de données en MongoDB (techno utilisées : Docker, MongoDB, Mongoose, mongo-express)

Ce projet a été initialisé avec le starter de la CLI [Nest](https://github.com/nestjs/nest).

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM Downloads" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://coveralls.io/github/nestjs/nest?branch=master" target="_blank"><img src="https://coveralls.io/repos/github/nestjs/nest/badge.svg?branch=master#9" alt="Coverage" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="Support us"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## 🚀 Installation du projet
***

- récupération du projet sur Github par HTTPS :

```shell script
$ https://github.com/tony-dugue/amazon-clone-nestjs-api.git
```

- installer les packages :
```shell script
$ yarn install
```

## Démarrer l'application
***
(1) démarrer l'application docker

(2) Démarrer le serveur de développement (à la racine du projet) :
```bash
$ yarn start #ou $ npm run start
```

Ou avec le watch mode
```bash
$ yarn start:dev #ou $ npm run start:dev
```

(3) dans le navigateur, visualisation de la base de données :
```bash
http://localhost:8081/
```

### Autres commandes

Démarrer les services dans docker :
```bash
$ docker-compose up -d
```

Voir les containers docker en cours de fonctionnement (si la bdd est bien démarrée) :
```bash
$ docker ps
```

Préparer l'application pour la production :
```bash
$ yarn start:prod #ou $ npm run start:prod
```

## Ressources utilisées dans le projet
***

[docker](https://www.docker.com/) <br />
Base de données : [MongoDB](https://www.mongodb.com/fr-fr) <br />
ODM : [mangoose](https://mongoosejs.com/) <br />
GUI base de données : [mongo-express](https://github.com/mongo-express/mongo-express/) <br />
Hachage des mots de passe : [Bcrypt](https://github.com/kelektiv/node.bcrypt.js) <br />
Authentification middleware pour Nodejs : [passport.js](https://www.passportjs.org/) <br />

## Nestjs Support
***

Nest is an [MIT licensed](LICENSE) open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

### Stay in touch

- Author - [Kamil Myśliwiec](https://kamilmysliwiec.com)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)
