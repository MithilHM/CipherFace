FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

# Ensure devDependencies (e.g., tailwindcss) are installed for dev server
RUN npm install --include=dev

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host"]
