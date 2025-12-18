const amqp = require('amqplib');

const RABBITMQ_URL = 'amqps://eyniqzwm:rk48-cJ2wGygWrXhkEivVAIWUZh4DsIN@moose.rmq.cloudamqp.com/eyniqzwm'; 

let channel = null;

const connectRabbitMQ = async (queueName) => {
    try {
        const connection = await amqp.connect(RABBITMQ_URL);
        channel = await connection.createChannel();
        await channel.assertQueue(queueName, { durable: true });
        console.log("Connected to RabbitMQ");
    } catch (error) {
        console.error("RabbitMQ Connection Error:", error);
    }
};

const publishMessage = async (queueName, data) => {
    if (!channel) await connectRabbitMQ();
    try {
        const msg = JSON.stringify(data);
        channel.sendToQueue(queueName, Buffer.from(msg), { persistent: true });
        console.log(`Sent message to MQ:`, data.type);
    } catch (error) {
        console.error("Error publishing message:", error);
    }
};

const consumeMessage = async (queueName, callback) => {
    if (!channel) await connectRabbitMQ();
    try {
        console.log("Waiting for messages...");
        channel.consume(queueName, (msg) => {
            if (msg !== null) {
                const content = JSON.parse(msg.content.toString());
                callback(content);
                channel.ack(msg);
            }
        });
    } catch (error) {
        console.error("Error consuming message:", error);
    }
};

module.exports = { connectRabbitMQ, publishMessage, consumeMessage };