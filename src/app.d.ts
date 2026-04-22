declare global {
	namespace App {
		interface Locals {
			user:
				| {
						id: number;
						githubId: number;
						username: string;
						email: string | null;
						avatar: string | null;
						status: 'active' | 'pending' | 'denied';
						isAdmin: boolean;
				  }
				| null;
			sessionId: string | null;
		}
	}
}

export {};
