import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth.models import AnonymousUser, User
from .serializers import TaskSerializer
from .models import Task

class TaskConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope['user']
        if user.is_authenticated:
            self.group_name = f'task_updates_{user.id}'
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            await self.send(text_data=json.dumps({'message': 'WebSocket connected successfully'}))  # Debug message
        else:
            await self.close(code=4001)

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def task_update(self, event):
        task = event['task']
        await self.send(text_data=json.dumps({
            'type': 'task_update',
            'task': task
        }))

    async def task_delete(self, event):
        task_id = event['task_id']
        await self.send(text_data=json.dumps({
            'type': 'task_delete',
            'task_id': task_id
        }))