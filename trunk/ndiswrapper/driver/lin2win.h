/*
 *  Copyright (C) 2006 Giridhar Pemmasani
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#ifdef CONFIG_X86_64

#if 1

/* Windows functions must have 32 bytes of reserved space above return
 * address, irrespective of number of args. So argc >= 4 */

#define alloc_win_stack_frame(argc)					\
	"subq $" #argc "*8, %%rsp\n\t"
#define free_win_stack_frame(argc)					\
	"addq $" #argc "*8, %%rsp\n\t"

/* m is index of Windows arg required, n is total number of args to
 * function Windows arg 1 should be at 0(%rsp), arg 2 at 8(%rsp) and
 * so on, after stack frame is allocated, which starts at -n*8(%rsp)
 * when stack frame is allocated. n should be > 4
*/

#define lin2win_win_arg(m,n) "(" #m "-1-" #n ")*8(%%rsp)"

/* volatile args for Windows function must be in clobber list */

#define LIN2WIN0(func)							\
({									\
	u64 ret;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %1, %%rax\n\t"					\
		alloc_win_stack_frame(4)				\
		"call *%%rax\n\t"					\
		free_win_stack_frame(4)					\
		"movq %%rax, %0\n\t"					\
		: "=g" (ret)						\
		: "g" ((u64)func)					\
		: "rax", "rcx", "rdx", "r8", "r9");			\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN1(func, arg1)						\
({									\
	u64 ret;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %1, %%rcx\n\t"					\
		"movq %2, %%rax\n\t"					\
		alloc_win_stack_frame(4)				\
		"call *%%rax\n\t"					\
		free_win_stack_frame(4)					\
		"movq %%rax, %0\n\t"					\
		: "=g" (ret)						\
		: "gi" ((u64)arg1),					\
		  "g" ((u64)func)					\
		: "rax", "rcx", "rdx", "r8", "r9");			\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN2(func, arg1, arg2)					\
({									\
	u64 ret;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %1, %%rcx\n\t"					\
		"movq %2, %%rdx\n\t"					\
		"movq %3, %%rax\n\t"					\
		alloc_win_stack_frame(4)				\
		"call *%%rax\n\t"					\
		free_win_stack_frame(4)					\
		"movq %%rax, %0\n\t"					\
		: "=g" (ret)						\
		: "gi" ((u64)arg1), "gi" ((u64)arg2),			\
		  "g" ((u64)func)					\
		: "rax", "rcx", "rdx", "r8", "r9");			\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN3(func, arg1, arg2, arg3)				\
({									\
	u64 ret;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %1, %%rcx\n\t"					\
		"movq %2, %%rdx\n\t"					\
		"movq %3, %%r8\n\t"					\
		"movq %4, %%rax\n\t"					\
		alloc_win_stack_frame(4)				\
		"call *%%rax\n\t"					\
		free_win_stack_frame(4)					\
		"movq %%rax, %0\n\t"					\
		: "=g" (ret)						\
		: "gi" ((u64)arg1), "gi" ((u64)arg2), "gi" ((u64)arg3),	\
		  "g" ((u64)func)					\
		: "rax", "rcx", "rdx", "r8", "r9");			\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN4(func, arg1, arg2, arg3, arg4)				\
({									\
	u64 ret;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %1, %%rcx\n\t"					\
		"movq %2, %%rdx\n\t"					\
		"movq %3, %%r8\n\t"					\
		"movq %4, %%r9\n\t"					\
		"movq %5, %%rax\n\t"					\
		alloc_win_stack_frame(4)				\
		"call *%%rax\n\t"					\
		free_win_stack_frame(4)					\
		"movq %%rax, %0\n\t"					\
		: "=g" (ret)						\
		: "gi" ((u64)arg1), "gi" ((u64)arg2), "gi" ((u64)arg3),	\
		  "gi" ((u64)arg4),					\
		  "g" ((u64)func)					\
		: "rax", "rcx", "rdx", "r8", "r9");			\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)			\
({									\
	u64 ret;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %1, %%rcx\n\t"					\
		"movq %2, %%rdx\n\t"					\
		"movq %3, %%r8\n\t"					\
		"movq %4, %%r9\n\t"					\
		"movq %5, %%rax\n\t"					\
		"movq %%rax, " lin2win_win_arg(5,5) "\n\t"		\
		"movq %6, %%rax\n\t"					\
		alloc_win_stack_frame(5)				\
		"call *%%rax\n\t"					\
		free_win_stack_frame(5)					\
		"movq %%rax, %0\n\t"					\
		: "=g" (ret)						\
		: "gi" ((u64)arg1), "gi" ((u64)arg2), "gi" ((u64)arg3),	\
		  "gi" ((u64)arg4), "gi" ((u64)arg5),			\
		  "g" ((u64)func)					\
		: "rax", "rcx", "rdx", "r8", "r9");			\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)		\
({									\
	u64 ret;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %1, %%rcx\n\t"					\
		"movq %2, %%rdx\n\t"					\
		"movq %3, %%r8\n\t"					\
		"movq %4, %%r9\n\t"					\
		"movq %5, %%rax\n\t"					\
		"movq %%rax, " lin2win_win_arg(5,6) "\n\t"		\
		"movq %6, %%rax\n\t"					\
		"movq %%rax, " lin2win_win_arg(6,6) "\n\t"		\
		"movq %7, %%rax\n\t"					\
		alloc_win_stack_frame(6)				\
		"call *%%rax\n\t"					\
		free_win_stack_frame(6)					\
		"movq %%rax, %0\n\t"					\
		: "=g" (ret)						\
		: "gi" ((u64)arg1), "gi" ((u64)arg2), "gi" ((u64)arg3),	\
		  "gi" ((u64)arg4), "gi" ((u64)arg5), "gi" ((u64)arg6), \
		  "g" ((u64)func)					\
		: "rax", "rcx", "rdx", "r8", "r9");			\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#else

u64 lin2win1(void *func, u64);
u64 lin2win2(void *func, u64, u64);
u64 lin2win3(void *func, u64, u64, u64);
u64 lin2win4(void *func, u64, u64, u64, u64);
u64 lin2win5(void *func, u64, u64, u64, u64, u64);
u64 lin2win6(void *func, u64, u64, u64, u64, u64, u64);

#define LIN2WIN1(func, arg1)						\
({									\
	DBGTRACE6("calling %p", func);					\
	lin2win1(func, (u64)arg1);					\
})
#define LIN2WIN2(func, arg1, arg2)					\
({									\
	DBGTRACE6("calling %p", func);					\
	lin2win2(func, (u64)arg1, (u64)arg2);				\
})
#define LIN2WIN3(func, arg1, arg2, arg3)				\
({									\
	DBGTRACE6("calling %p", func);					\
	lin2win3(func, (u64)arg1, (u64)arg2, (u64)arg3);		\
})
#define LIN2WIN4(func, arg1, arg2, arg3, arg4)				\
({									\
	DBGTRACE6("calling %p", func);					\
	lin2win4(func, (u64)arg1, (u64)arg2, (u64)arg3, (u64)arg4);	\
})
#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)			\
({									\
	DBGTRACE6("calling %p", func);					\
	lin2win5(func, (u64)arg1, (u64)arg2, (u64)arg3, (u64)arg4,	\
		 (u64)arg5);						\
})
#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)		\
({									\
	DBGTRACE6("calling %p", func);					\
	lin2win6(func, (u64)arg1, (u64)arg2, (u64)arg3, (u64)arg4,	\
		 (u64)arg5, (u64)arg6);					\
})

#endif

#else // CONFIG_X86_64

#define LIN2WIN1(func, arg1)						\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1);							\
})
#define LIN2WIN2(func, arg1, arg2)					\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2);						\
})
#define LIN2WIN3(func, arg1, arg2, arg3)				\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3);						\
})
#define LIN2WIN4(func, arg1, arg2, arg3, arg4)				\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3, arg4);					\
})
#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)			\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3, arg4, arg5);				\
})
#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)		\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3, arg4, arg5, arg6);			\
})

#endif // CONFIG_X86_64
