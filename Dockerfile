# Use the official Node.js image as a base
FROM node:18

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5001

# Use the "npm start" -command to run the app
CMD ["npm", "start"]