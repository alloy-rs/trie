use alloc::vec::Vec;

/// A simple arena allocator for managing object lifetimes efficiently.
/// 
/// This arena reduces allocation overhead by pre-allocating chunks of memory
/// and providing stack-like allocation/deallocation semantics. Perfect for
/// HashBuilder's stack operations where elements are pushed and popped
/// in LIFO order.
#[derive(Debug, Clone)]
pub struct Arena<T> 
where
    T: Clone,
{
    /// Storage for allocated items
    items: Vec<T>,
    /// Capacity to pre-allocate to avoid frequent reallocations
    capacity: usize,
}

impl<T> Arena<T> 
where
    T: Clone,
{
    /// Creates a new arena with the specified initial capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Creates a new arena with a default capacity suitable for trie operations.
    /// 
    /// Uses 128 as default since most tries don't exceed 65 levels deep
    /// and branch nodes typically have multiple children.
    #[inline]
    pub fn new() -> Self {
        Self::with_capacity(128)
    }

    /// Pushes an item into the arena and returns a handle to it.
    #[inline]
    pub fn push(&mut self, item: T) -> ArenaIndex {
        let index = self.items.len();
        self.items.push(item);
        ArenaIndex(index)
    }

    /// Gets a reference to an item by its arena index.
    #[inline]
    pub fn get(&self, index: ArenaIndex) -> Option<&T> {
        self.items.get(index.0)
    }

    /// Gets a mutable reference to an item by its arena index.
    #[inline]
    pub fn get_mut(&mut self, index: ArenaIndex) -> Option<&mut T> {
        self.items.get_mut(index.0)
    }

    /// Returns the current number of items in the arena.
    #[inline]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if the arena is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Gets the last item in the arena.
    #[inline]
    pub fn last(&self) -> Option<&T> {
        self.items.last()
    }

    /// Gets a mutable reference to the last item in the arena.
    #[inline]
    pub fn last_mut(&mut self) -> Option<&mut T> {
        self.items.last_mut()
    }

    /// Pops the last item from the arena.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }

    /// Resizes the arena to the specified length.
    /// 
    /// If `new_len` is greater than the current length, the arena is
    /// extended with default values. If less, items are truncated.
    #[inline]
    pub fn resize_with<F>(&mut self, new_len: usize, f: F)
    where
        F: FnMut() -> T,
    {
        self.items.resize_with(new_len, f);
    }

    /// Truncates the arena to the specified length.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.items.truncate(len);
    }

    /// Clears all items from the arena but retains the allocated capacity.
    #[inline]
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Returns an iterator over the items in the arena.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.items.iter()
    }

    /// Returns a mutable iterator over the items in the arena.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.items.iter_mut()
    }

    /// Returns the current capacity of the arena.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.items.capacity()
    }

    /// Returns a slice view of all items in the arena.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    /// Returns a mutable slice view of all items in the arena.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.items
    }
}

impl<T> Default for Arena<T> 
where
    T: Clone,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// An index into an arena, providing safe access to arena-allocated items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArenaIndex(usize);

impl ArenaIndex {
    /// Creates a new arena index from a raw index value.
    #[inline]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the raw index value.
    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// A stack-like data structure built on top of an arena allocator.
/// 
/// This provides the same API as `Vec<T>` for stack operations but uses
/// an arena for more efficient memory management. Items remain allocated
/// until the entire stack is cleared, reducing allocation overhead.
#[derive(Debug, Clone)]
pub struct ArenaStack<T> 
where
    T: Clone,
{
    arena: Arena<T>,
    /// Track the logical "top" of the stack to allow efficient resize operations
    top: usize,
}

impl<T> ArenaStack<T> 
where
    T: Clone,
{
    /// Creates a new arena stack with the specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            arena: Arena::with_capacity(capacity),
            top: 0,
        }
    }

    /// Creates a new arena stack with default capacity.
    #[inline]
    pub fn new() -> Self {
        Self::with_capacity(128)
    }

    /// Pushes an item onto the stack.
    #[inline]
    pub fn push(&mut self, item: T) {
        if self.top < self.arena.len() {
            // Reuse existing slot
            self.arena.items[self.top] = item;
        } else {
            // Need to grow
            self.arena.push(item);
        }
        self.top += 1;
    }

    /// Pops an item from the stack.
    #[inline]
    pub fn pop(&mut self) -> Option<T> 
    where 
        T: Default,
    {
        if self.top == 0 {
            None
        } else {
            self.top -= 1;
            // Replace with default to avoid keeping references
            let item = core::mem::take(&mut self.arena.items[self.top]);
            Some(item)
        }
    }

    /// Returns a reference to the last item on the stack.
    #[inline]
    pub fn last(&self) -> Option<&T> {
        if self.top == 0 {
            None
        } else {
            self.arena.items.get(self.top - 1)
        }
    }

    /// Returns the number of items on the stack.
    #[inline]
    pub fn len(&self) -> usize {
        self.top
    }

    /// Returns true if the stack is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.top == 0
    }

    /// Resizes the stack to the specified length.
    #[inline]
    pub fn resize_with<F>(&mut self, new_len: usize, mut f: F)
    where
        F: FnMut() -> T,
    {
        if new_len > self.top {
            // Growing the stack - fill new positions
            for i in self.top..new_len {
                if i < self.arena.items.len() {
                    // Reuse existing slot
                    self.arena.items[i] = f();
                } else {
                    // Need to grow the arena
                    self.arena.items.push(f());
                }
            }
        }
        // For shrinking (new_len < self.top), we just update the top pointer
        self.top = new_len;
    }

    /// Clears the stack.
    #[inline]
    pub fn clear(&mut self) {
        self.top = 0;
    }

    /// Returns an iterator over the items currently on the stack.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.arena.items[..self.top].iter()
    }

    /// Returns the current capacity of the underlying arena.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.arena.capacity()
    }

    /// Returns a slice view of the items currently on the stack.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.arena.items[..self.top]
    }
}

impl<'a, T> IntoIterator for &'a ArenaStack<T> 
where
    T: Clone,
{
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> Default for ArenaStack<T> 
where
    T: Clone,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_basic_operations() {
        let mut arena: Arena<i32> = Arena::new();
        
        let idx1 = arena.push(42);
        let idx2 = arena.push(84);
        
        assert_eq!(arena.get(idx1), Some(&42));
        assert_eq!(arena.get(idx2), Some(&84));
        assert_eq!(arena.len(), 2);
        
        assert_eq!(arena.pop(), Some(84));
        assert_eq!(arena.len(), 1);
    }

    #[test]
    fn arena_stack_operations() {
        let mut stack: ArenaStack<i32> = ArenaStack::new();
        
        stack.push(1);
        stack.push(2);
        stack.push(3);
        
        assert_eq!(stack.len(), 3);
        assert_eq!(stack.last(), Some(&3));
        
        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        assert_eq!(stack.len(), 1);
        
        // Test reuse after pop
        stack.push(4);
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.last(), Some(&4));
    }

    #[test]
    fn arena_stack_resize() {
        let mut stack: ArenaStack<i32> = ArenaStack::with_capacity(2);
        
        stack.push(1);
        stack.push(2);
        
        // Resize down
        stack.resize_with(1, || 0);
        assert_eq!(stack.len(), 1);
        
        // Resize up - should extend with new values
        stack.resize_with(3, || 42);
        assert_eq!(stack.len(), 3);
        // Note: Unlike Vec, arena may preserve old values between top and capacity
        // The important thing is that the visible slice has the right length and new values are added
        assert_eq!(stack.as_slice().len(), 3);
        assert_eq!(stack.as_slice()[0], 1);
        assert_eq!(stack.as_slice()[1], 42);
        assert_eq!(stack.as_slice()[2], 42);
    }
}