import requests
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class DiscordNotifier:
    """
    A class to send beautifully formatted notifications to Discord via webhooks.
    
    Features:
    - Rich embeds with colors
    - Multiple notification types (success, error, warning, info)
    - Support for fields, thumbnails, and images
    - Rate limiting awareness
    """
    
    # Color scheme for different notification types
    COLORS = {
        "success": 0x00FF00,  # Green
        "error": 0xFF0000,    # Red
        "warning": 0xFFA500,  # Orange
        "info": 0x0099FF,     # Blue
        "security": 0xFF00FF, # Magenta
        "default": 0x808080   # Gray
    }
    
    def __init__(self, webhook_url: str, username: str = "MyDJ Server", avatar_url: Optional[str] = None):
        """
        Initialize the Discord notifier.
        
        Args:
            webhook_url: Discord webhook URL
            username: Bot username to display
            avatar_url: URL to bot avatar image
        """
        self.webhook_url = webhook_url
        self.username = username
        self.avatar_url = avatar_url
    
    def send_embed(
        self,
        title: str,
        description: str = "",
        color: str = "default",
        fields: Optional[List[Dict[str, Any]]] = None,
        thumbnail: Optional[str] = None,
        image: Optional[str] = None,
        footer: Optional[str] = None,
        timestamp: bool = True
    ) -> bool:
        """
        Send a rich embed message to Discord.
        
        Args:
            title: Embed title
            description: Embed description
            color: Color type (success, error, warning, info, security, default)
            fields: List of field dictionaries with 'name', 'value', and optional 'inline'
            thumbnail: URL to thumbnail image
            image: URL to main image
            footer: Footer text
            timestamp: Whether to include timestamp
            
        Returns:
            bool: True if successful, False otherwise
        """
        embed = {
            "title": title,
            "description": description,
            "color": self.COLORS.get(color, self.COLORS["default"])
        }
        
        # Add fields
        if fields:
            embed["fields"] = []
            for field in fields:
                embed["fields"].append({
                    "name": field.get("name", "Field"),
                    "value": field.get("value", ""),
                    "inline": field.get("inline", False)
                })
        
        # Add thumbnail
        if thumbnail:
            embed["thumbnail"] = {"url": thumbnail}
        
        # Add image
        if image:
            embed["image"] = {"url": image}
        
        # Add footer
        if footer:
            embed["footer"] = {"text": footer}
        
        # Add timestamp
        if timestamp:
            embed["timestamp"] = datetime.utcnow().isoformat()
        
        payload = {
            "username": self.username,
            "embeds": [embed]
        }
        
        if self.avatar_url:
            payload["avatar_url"] = self.avatar_url
        
        return self._send_webhook(payload)
    
    def send_jurnal_notification(
        self,
        kelas: str,
        mapel: str,
        jam: int,
        tujuan: str,
        materi: str,
        kegiatan: str,
        dimensi: str,
        created_at: str,
        has_image: bool = False,
        has_video: bool = False
    ) -> bool:
        """
        Send a notification for a new jurnal upload.
        
        Args:
            kelas: Class name
            mapel: Subject
            jam: Hour/period
            tujuan: Learning objective
            materi: Learning material/topic
            kegiatan: Learning activities
            dimensi: Pancasila student profile dimension
            created_at: Creation timestamp
            has_image: Whether image was uploaded
            has_video: Whether video was uploaded
            
        Returns:
            bool: True if successful, False otherwise
        """
        media_icons = []
        if has_image:
            media_icons.append("📷 Image")
        if has_video:
            media_icons.append("🎥 Video")
        media_text = " | ".join(media_icons) if media_icons else "No media"
        
        fields = [
            {"name": "📚 Kelas", "value": kelas, "inline": True},
            {"name": "📖 Mapel", "value": mapel, "inline": True},
            {"name": "⏰ Jam", "value": f"Jam ke-{jam}", "inline": True},
            {"name": "🎯 Tujuan Pembelajaran", "value": tujuan[:100] + "..." if len(tujuan) > 100 else tujuan, "inline": False},
            {"name": "📝 Materi/Topik", "value": materi[:100] + "..." if len(materi) > 100 else materi, "inline": False},
            {"name": "🎭 Kegiatan Pembelajaran", "value": kegiatan[:100] + "..." if len(kegiatan) > 100 else kegiatan, "inline": False},
            {"name": "🌟 Dimensi Profil Pelajar Pancasila", "value": dimensi, "inline": False},
            {"name": "📎 Media", "value": media_text, "inline": False},
        ]
        
        return self.send_embed(
            title="✅ Jurnal Baru Berhasil Di-upload!",
            description=f"Jurnal pembelajaran telah ditambahkan pada {created_at}",
            color="success",
            fields=fields,
            footer="MyDJ Server - Jurnal Management System"
        )
    
    def send_security_alert(
        self,
        alert_type: str,
        ip_address: str,
        details: str,
        severity: str = "warning"
    ) -> bool:
        """
        Send a security alert notification.
        
        Args:
            alert_type: Type of security alert
            ip_address: IP address involved
            details: Alert details
            severity: Severity level (warning, error, security)
            
        Returns:
            bool: True if successful, False otherwise
        """
        severity_icons = {
            "warning": "⚠️",
            "error": "🚨",
            "security": "🔒"
        }
        
        icon = severity_icons.get(severity, "⚠️")
        
        fields = [
            {"name": "🔍 Alert Type", "value": alert_type, "inline": True},
            {"name": "🌐 IP Address", "value": ip_address, "inline": True},
            {"name": "📋 Details", "value": details, "inline": False},
        ]
        
        return self.send_embed(
            title=f"{icon} Security Alert",
            description="A security event has been detected",
            color=severity,
            fields=fields,
            footer="MyDJ Server - Security Monitoring",
            timestamp=True
        )
    
    def send_rate_limit_alert(
        self,
        ip_address: str,
        endpoint: str,
        attempts: int
    ) -> bool:
        """
        Send a rate limit exceeded notification.
        
        Args:
            ip_address: IP address that exceeded limit
            endpoint: API endpoint
            attempts: Number of attempts
            
        Returns:
            bool: True if successful, False otherwise
        """
        fields = [
            {"name": "🌐 IP Address", "value": ip_address, "inline": True},
            {"name": "🔗 Endpoint", "value": endpoint, "inline": True},
            {"name": "🔢 Attempts", "value": str(attempts), "inline": True},
        ]
        
        return self.send_embed(
            title="⚠️ Rate Limit Exceeded",
            description="A client has exceeded the rate limit",
            color="warning",
            fields=fields,
            footer="MyDJ Server - Rate Limiting"
        )
    
    def send_error_notification(
        self,
        error_type: str,
        error_message: str,
        traceback: Optional[str] = None
    ) -> bool:
        """
        Send an error notification.
        
        Args:
            error_type: Type of error
            error_message: Error message
            traceback: Optional traceback information
            
        Returns:
            bool: True if successful, False otherwise
        """
        fields = [
            {"name": "❌ Error Type", "value": error_type, "inline": False},
            {"name": "💬 Message", "value": error_message[:1000], "inline": False},
        ]
        
        if traceback:
            fields.append({
                "name": "📜 Traceback",
                "value": f"```\n{traceback[:500]}\n```",
                "inline": False
            })
        
        return self.send_embed(
            title="🚨 Application Error",
            description="An error has occurred in the application",
            color="error",
            fields=fields,
            footer="MyDJ Server - Error Monitoring"
        )
    
    def send_simple_message(self, message: str) -> bool:
        """
        Send a simple text message without embeds.
        
        Args:
            message: Message text
            
        Returns:
            bool: True if successful, False otherwise
        """
        payload = {
            "username": self.username,
            "content": message
        }
        
        if self.avatar_url:
            payload["avatar_url"] = self.avatar_url
        
        return self._send_webhook(payload)
    
    def _send_webhook(self, payload: Dict[str, Any]) -> bool:
        """
        Internal method to send webhook request.
        
        Args:
            payload: Webhook payload
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 204:
                logger.info("Discord notification sent successfully")
                return True
            elif response.status_code == 429:
                logger.warning("Discord rate limit exceeded")
                return False
            else:
                logger.error(f"Discord webhook failed with status {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send Discord notification: {str(e)}")
            return False
