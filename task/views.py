from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.http import Http404
from .models import Task
from .serializers import TaskSerializer
from accounts.models import Permission
from django.db.models import Q
from datetime import datetime
from django.core.cache import cache


class TaskView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Generate cache key based on user and query parameters
        query_params = request.query_params.urlencode()
        cache_key = f'tasks_{request.user.id}_{query_params}'
        cached_tasks = cache.get(cache_key)
        if cached_tasks:
            return Response({
                'success': True,
                'status': 200,
                'message': 'Tasks retrieved successfully (cached)',
                'data': cached_tasks
            }, status=status.HTTP_200_OK)

        # Check if user has 'view_tasks' permission or is Admin
        if request.user.role != 'Admin' and not Permission.objects.filter(user=request.user, permission_name='view_tasks').exists():
            return Response({
                'success': False,
                'status': 403,
                'message': 'You do not have permission to view tasks'
            }, status=status.HTTP_200_OK)

        # Advanced filtering
        tasks = Task.objects.all()
        if request.user.role != 'Admin':
            tasks = tasks.filter(Q(assigned_to=request.user) | Q(created_by=request.user))

        # Filter by status
        task_status = request.query_params.get('status')
        if task_status:
            tasks = tasks.filter(status=task_status)

        # Filter by priority
        priority = request.query_params.get('priority')
        if priority:
            tasks = tasks.filter(priority=priority)

        # Filter by due date range
        due_date_start = request.query_params.get('due_date_start')
        due_date_end = request.query_params.get('due_date_end')
        if due_date_start:
            tasks = tasks.filter(due_date__gte=datetime.fromisoformat(due_date_start))
        if due_date_end:
            tasks = tasks.filter(due_date__lte=datetime.fromisoformat(due_date_end))

        # Filter by assigned user (Admin only)
        assigned_to = request.query_params.get('assigned_to')
        if assigned_to and request.user.role == 'Admin':
            tasks = tasks.filter(assigned_to__id=assigned_to)

        serializer = TaskSerializer(tasks, many=True)
        # Cache the serialized data for 15 minutes
        cache.set(cache_key, serializer.data, timeout=60*15)
        return Response({
            'success': True,
            'status': 200,
            'message': 'Tasks retrieved successfully',
            'data': serializer.data
        }, status=status.HTTP_200_OK)

    def post(self, request):
        # Check if user has 'manage_tasks' permission (or is Admin)
        if not Permission.objects.filter(user=request.user, permission_name='manage_tasks').exists():
            return Response({
                'success': False,
                'status': 403,
                'message': 'You do not have permission to create tasks'
            }, status=status.HTTP_200_OK)

        serializer = TaskSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            task = serializer.save()
            # Invalidate cache for the assigned user and creator
            cache_key_assigned = f'tasks_{task.assigned_to.id if task.assigned_to else 0}_'
            cache_key_creator = f'tasks_{task.created_by.id}_'
            cache.delete_pattern(f'{cache_key_assigned}*')
            cache.delete_pattern(f'{cache_key_creator}*')
            # Notify WebSocket consumers
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            channel_layer = get_channel_layer()
            event = {
                'type': 'task_update',
                'task': TaskSerializer(task).data
            }
            # Send to assigned_to (fallback to creator if no assigned_to)
            assigned_group = f'task_updates_{task.assigned_to.id if task.assigned_to else task.created_by.id}'
            async_to_sync(channel_layer.group_send)(assigned_group, event)
            # Notify creator separately if different from assigned_to
            if task.assigned_to and task.assigned_to.id != task.created_by.id:
                creator_group = f'task_updates_{task.created_by.id}'
                async_to_sync(channel_layer.group_send)(creator_group, event)
            return Response({
                'success': True,
                'status': 201,
                'message': 'Task created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            'success': False,
            'status': 400,
            'message': serializer.errors
        }, status=status.HTTP_200_OK)


class TaskDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Task.objects.get(pk=pk)
        except Task.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        task = self.get_object(pk)
        # Check if user has 'view_tasks' permission and access to this task
        if not Permission.objects.filter(user=request.user, permission_name='view_tasks').exists():
            return Response({   
                'success': False,
                'status': 403,
                'message': 'You do not have permission to view tasks'
            }, status=status.HTTP_200_OK)
        if request.user.role != 'Admin' and task.assigned_to != request.user and task.created_by != request.user:
            return Response({
                'success': False,
                'status': 403,
                'message': 'You can only view your own tasks'
            }, status=status.HTTP_200_OK)

        serializer = TaskSerializer(task)
        return Response({
            'success': True,
            'status': 200,
            'message': 'Task retrieved successfully',
            'data': serializer.data
        }, status=status.HTTP_200_OK)

    def put(self, request, pk):
        task = self.get_object(pk)
        # Check if user has 'manage_tasks' permission (Admins) or 'update_task_status' (Users)
        if request.user.role != 'Admin' and not Permission.objects.filter(
            user=request.user, permission_name='update_task_status'
        ).exists():
            return Response({
                'success': False,
                'status': 403,
                'message': 'You do not have permission to update tasks'
            }, status=status.HTTP_200_OK)
        if request.user.role != 'Admin' and task.assigned_to != request.user:
            return Response({
                'success': False,
                'status': 403,
                'message': 'You can only update your own tasks'
            }, status=status.HTTP_200_OK)

        serializer = TaskSerializer(task, data=request.data, partial=True)
        if serializer.is_valid():
            task = serializer.save()
            # Invalidate cache for the assigned user and creator
            cache_key_assigned = f'tasks_{task.assigned_to.id if task.assigned_to else 0}_'
            cache_key_creator = f'tasks_{task.created_by.id}_'
            cache.delete_pattern(f'{cache_key_assigned}*')
            cache.delete_pattern(f'{cache_key_creator}*')
            # Notify WebSocket consumers
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            channel_layer = get_channel_layer()
            event = {
                'type': 'task_update',
                'task': TaskSerializer(task).data
            }
            # Send to assigned_to (fallback to creator if no assigned_to)
            assigned_group = f'task_updates_{task.assigned_to.id if task.assigned_to else task.created_by.id}'
            async_to_sync(channel_layer.group_send)(assigned_group, event)
            # Notify creator separately if different from assigned_to
            if task.assigned_to and task.assigned_to.id != task.created_by.id:
                creator_group = f'task_updates_{task.created_by.id}'
                async_to_sync(channel_layer.group_send)(creator_group, event)
            return Response({
                'success': True,
                'status': 200,
                'message': 'Task updated successfully',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
        return Response({
            'success': False,
            'status': 400,
            'message': serializer.errors
        }, status=status.HTTP_200_OK)

    def delete(self, request, pk):
        # Only Admins with 'manage_tasks' permission can delete
        if not Permission.objects.filter(user=request.user, permission_name='manage_tasks').exists():
            return Response({
                'success': False,
                'status': 403,
                'message': 'You do not have permission to delete tasks'
            }, status=status.HTTP_200_OK)

        task = self.get_object(pk)
        # Invalidate cache for the assigned user and creator
        cache_key_assigned = f'tasks_{task.assigned_to.id if task.assigned_to else 0}_'
        cache_key_creator = f'tasks_{task.created_by.id}_'
        cache.delete_pattern(f'{cache_key_assigned}*')
        cache.delete_pattern(f'{cache_key_creator}*')
        # Store details before deleting
        assigned_id = task.assigned_to.id if task.assigned_to else task.created_by.id
        creator_id = task.created_by.id
        task.delete()
        # Notify WebSocket consumers
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        channel_layer = get_channel_layer()
        event = {
            'type': 'task_delete',
            'task_id': pk
        }
        # Send to assigned_to (fallback to creator if no assigned_to)
        assigned_group = f'task_updates_{assigned_id}'
        async_to_sync(channel_layer.group_send)(assigned_group, event)
        # Notify creator separately if different from assigned_to
        if assigned_id != creator_id:
            creator_group = f'task_updates_{creator_id}'
            async_to_sync(channel_layer.group_send)(creator_group, event)
        return Response({
            'success': True,
            'status': 204,
            'message': 'Task deleted successfully'
        }, status=status.HTTP_200_OK)
